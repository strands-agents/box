# Release signed and notarized macOS builds

The `Release Box` workflow builds the macOS product with `native-filesystem-policy`.
The runtime experiment remains opt-in through `box.toml`.
Signing authorizes Endpoint Security access; it does not activate the experiment.

## Configure access

Create a GitHub environment named `macos-signing`.
Restrict deployments to `main` and require a release owner to approve access.
Keep the existing `release-gate` environment for publication approval.

Create an AWS role for GitHub's OpenID Connect identity.
OpenID Connect lets a workflow obtain temporary AWS credentials without a stored AWS access key.
Restrict its trust policy to audience `sts.amazonaws.com` and the exact subject reported by the repository's identity configuration.
With immutable repository identities enabled, the subject includes the organization and repository IDs before `:environment:macos-signing`.
Read that configuration with `gh api repos/strands-agents/box/actions/oidc/customization/sub`; do not assume the older name-only format.
The environment's branch restriction is required because that subject does not include the branch.

Grant only the signing API calls, access to the designated signing bucket prefixes, and permission to pass the bucket-access role.
The signing service must be able to assume that bucket-access role.
Complete the service's application authorization for the caller account before a signed run.
The workflow does not create roles, change their policies, or claim application ownership.

Store the notarization credential in AWS Secrets Manager as a JSON object.
The secret holds one of two credentials:

| Credential | JSON fields |
|---|---|
| App Store Connect API key | `key_id` holds the key ID, and `private_key` holds the complete contents of the downloaded `.p8` file. |
| Apple ID with an app-specific password | `apple_id` holds the Apple ID, and `app_specific_password` holds the password in its `xxxx-xxxx-xxxx-xxxx` form. |

Prefer an API key of a shared automation account.
Use an individual key, not a team key, because the job passes no issuer ID.
An app-specific password is a personal credential of one Apple ID.
Until its owner revokes it, the caller role and the administrators of the secret's account can notarize as that Apple ID.
Apple also revokes it when the password of that Apple ID changes.
The account of either credential must be able to notarize for the signing team.
The job finds the credential type from the JSON fields.
To change the credential, replace the secret value. The variable and the workflow do not change.
Then revoke the replaced credential, because Secrets Manager keeps the replaced value as the previous version of the secret.
Grant the caller role `secretsmanager:GetSecretValue` on that secret and on no other secret.
If a customer managed key encrypts the secret, also grant `kms:Decrypt` on that key.

Set these required variables in `macos-signing` before a signed run:

| Variable | Value |
|---|---|
| `CD_SIGNER_CALLER_ROLE` | AWS role that GitHub assumes to call the signing API and transfer archives. |
| `CD_SIGNER_REGION` | Region for AWS credentials and signing API requests. |
| `CD_SIGNER_ENDPOINT` | HTTPS origin of the signing API. |
| `CD_SIGNER_BUCKET` | Bucket for unsigned and signed artifacts. |
| `CD_SIGNER_BUCKET_ACCESS_ROLE` | Role that the signing service assumes for that bucket. |
| `CD_SIGNER_TEAM_ID` | Apple team that owns the signing certificate and profile. |
| `CD_SIGNER_PROFILE_NAME` | Required for signing and verification: the exact Developer ID profile name for `com.amazon.strands.box`. |
| `NOTARY_CREDENTIAL_SECRET` | ARN of the Secrets Manager secret that holds the notarization credential. |

The signing client rejects a missing or blank profile name.
It also rejects a `NOTARY_CREDENTIAL_SECRET` value that is not a Secrets Manager ARN, so an unset variable stops the run.
It rejects a secret that does not have one of the JSON forms above, or that has fields of both forms.
The profile must authorize `com.apple.developer.endpoint-security.client` for the application and its signing certificate.
The application manifest sets both `profile_name` and `profile_type: distribution`.
The latter enables profile fetching in the macOS signing path.
The signed application includes the profile, and verification checks its identity, expiration, and certificate authorization.
This supplies the Apple authorization needed by the native Endpoint Security feature.
It does not enable the runtime experiment or replace native enforcement tests.
Unsigned dry runs do not need these signing variables.
Account-specific values and access requests belong in the team's internal runbook.

## Run a dry run

Run `Release Box` with `dry_run=true` to build and inspect without signing credentials.
These unsigned artifacts are for inspection and do not qualify native enforcement.
Forks support only unsigned dry runs.
The protected premerge mode below also permits a signed test from one upstream workflow branch.

For the complete signing test, dispatch from upstream `main` with `dry_run=true` and `sign_macos=true`.
Select a source commit in `main` history.
Approve the `macos-signing` environment request.
This run signs, notarizes, and tests the package, but does not publish a GitHub release.

The macOS jobs use the `xcode-27` hosted runner.
The macOS build needs the macOS 27 SDK or later.
The signed test runner also needs macOS 27 or later.
The workflow refuses older hosts instead of reporting native qualification.

## Test signing before merge

Create a separate `macos-signing-test` environment in the upstream repository.
Allow only `feature/macos-release-notarization`, require a Box maintainer's approval, prevent self-review, and disable administrator bypass.
Use a separate, limited AWS test role that trusts this environment's exact identity.
Set the same eight variables listed above, with the test role as `CD_SIGNER_CALLER_ROLE`.
Keep these permissions separate from the production `macos-signing` environment.

Review the complete candidate workflow and scripts before approving a run.
Set `SIGNING_TEST_WORKFLOW_SHA` to that full, reviewed workflow commit.
Set `SIGNING_TEST_SOURCE_SHA` to the full product commit from `main` history.
These environment variables must contain 40 lowercase hexadecimal characters.
The signing job checks both values before checkout or AWS credential access.
A branch update requires another reviewed workflow pin.
The pin check guards accidental changes; the environment reviewer must still inspect the workflow that enforces it.

Dispatch `Release Box` from `feature/macos-release-notarization` with:

- `dry_run=true`
- `sign_macos=true`
- `premerge_signing_test=true`
- `skip_tests=false`
- `sha` equal to `SIGNING_TEST_SOURCE_SHA`
- A valid next version, such as `0.1.1` after `v0.1.0`.

A different Box maintainer must approve the environment request.
This mode rejects forks, other branches, unmerged product sources, and requests to publish.
The production signing path still requires upstream `main`.
The separate verification job runs without AWS credentials and uses the reviewed workflow's native tests.
Record the run URL and results before removing the temporary role and environment.
A successful premerge run does not replace qualification of the merged production workflow and its production role.

## Inspect a signed run

The signing job downloads the macOS build from the same workflow run.
It signs the two helpers first, then includes them in `Box.app` before signing the main application.
The final archive contains that bundle, a `box` launcher, and helper links into `Contents/MacOS`.
The public command remains `./box-core/box`.
The launcher executes the bundle's real path so Box finds its regular helper files beside the main executable.

The signing job verifies signatures, application identity, the Endpoint Security entitlement, and the embedded profile.
It checks that the profile authorizes the signing certificate.
It also checks the hardened-runtime flag, signing timestamp, and unchanged signed helper bytes.
Each request uses unique S3 object keys.

Before the first signing request, the job confirms that Apple accepts the notarization credential.
A refused credential stops the run before any signing.
The job writes an API key to a temporary file that only its user can read, and removes the file after use.
It gives an app-specific password to `notarytool` on standard input, not as a command argument.
It does not print the Apple ID or the password.
It removes both from the `notarytool` output that the job reports in errors or saves as evidence.
After the signing checks, the job puts `Box.app` in a zip archive and submits the archive to Apple's notary service.
It waits up to 30 minutes for the result, and continues only when Apple accepts the submission.
Apple then issues a notarization ticket, which is a signed record of the accepted submission.
The job staples the ticket to `Box.app`, so Gatekeeper can check the ticket without a network connection.
The ticket is sometimes not available immediately, so the job makes up to five stapling attempts, 30 seconds apart.
It confirms the stapled ticket, then confirms Apple's notarization of the bundle and its three executables.
Then it creates the archive.

The signing and verification jobs cannot read or write GitHub Actions caches.
A separate job extracts the final archive without AWS credentials.
Its verification tools and native tests come from the commit that contains the running workflow.
The selected release source supplies the package, but cannot replace the tests that approve it.
It verifies the extracted application's signatures and stapled notarization ticket, then runs its `box --version` entry point.
It then runs the complete native test package against that same `box` path.
An older source must pass the workflow commit's current tests before publication.
Any signing, verification, or native-test failure blocks publication.

Inspect the `macos-signing-evidence` and `macos-package-verification` workflow artifacts.
Keep these items with release evidence: the source and verification SHAs, the signing task IDs, and the notarization submission ID.
Also keep the package hashes, the verification output, and the native-test log.
The signing evidence also contains Apple's notarization log if `notarytool` downloaded it.
The source SHA identifies the product source; the verification SHA identifies the workflow and test source.
The package hash identifies the exact distributed bytes.

## Publish

Run `Release Box` from upstream `main` with `dry_run=false`.
Signing, notarization, and native tests are mandatory in this mode.
After all checks pass, approve `release-gate` to publish.
The release job publishes the verified package without rebuilding it.
The final checksum file covers the signed and notarized archive.
Before publication, the inspection job confirms that the macOS archive contains the stapled ticket.

The workflow does not launch a copy of the archive that a browser downloaded.
To check that path, download the macOS archive in a browser, and then run these commands in the download directory:

```sh
mkdir box-core
tar -C box-core -xzf box-<tag>-aarch64-apple-darwin.tar.gz
./box-core/box --version
```

The `tar` that ships with macOS copies the download's quarantine flag to each extracted file, so Gatekeeper checks `box` when it starts.
If macOS shows a prompt instead of the version, the package is not notarized.

## Test changes to packaging

Run `python3 -m unittest discover -s scripts -p 'test_*.py' -v`.
These tests cover archive rejection, bundle assembly, profile selection, notarization credential checks, notarization result checks, source restrictions, and release asset selection.
They require no AWS or Apple credentials.
Run an upstream signed dry run before accepting changes to signing behavior.

A local run of `scripts/macos-release.py sign` signs through the signing service, the same as the workflow.
It needs AWS credentials, `AWS_REGION`, `CD_SIGNER_ENDPOINT`, `CD_SIGNER_BUCKET`, `CD_SIGNER_BUCKET_ACCESS_ROLE`, `CD_SIGNER_TEAM_ID`, and `CD_SIGNER_PROFILE_NAME`.
For notarization, pass `--notary-keychain-profile` instead of `--notary-secret`.
Use a profile that `xcrun notarytool store-credentials` created.
