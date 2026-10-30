# AWS credential prototype

This throwaway prototype uses the Rust SDK for both automatic AWS credential discovery and explicit profiles. It is for evaluation, not release. Neither path uses `credsd`.

## Build and run

From the repository root:

```sh
cargo build -p strands-box --all-features --bins --locked
cargo build -p strands-box-containment --all-features \
  --bin strands-box-contain-trampoline --locked
```

To use the standard Rust SDK credential chain:

```toml
[egress.aws]
destinations = ["sts.us-east-1.amazonaws.com"]
secret.ref = "aws-chain://"
```

The reference has no selector. Box uses the standard `aws-config` chain with SSO and credential-process support. Its HTTP client uses Ring, which matches Box's existing TLS provider. The chain checks environment credentials, shared AWS profiles, web identity, container credentials, and EC2 instance metadata, in that order. `AWS_PROFILE` selects the shared profile; exported credentials take precedence. Profile providers include SSO, AssumeRole, and `credential_process`. The SDK's optional `credentials-login` feature is not enabled.

Discovery uses the trusted Box process's environment and AWS configuration. The workload receives example credentials. Box signs permitted requests with the real credentials. `aws-env://default` is no longer accepted; environment credentials now work through the chain.

Run the smoke check with the host's current AWS configuration:

```sh
python3 crates/box/prototype-aws/run.py chain
```

Use `chain --profile bedrock` to set `AWS_PROFILE` for the check. Use `chain --seed-profile bedrock` to fetch credentials through that profile's helper in the parent process and pass them to Box as environment variables. This checks the environment provider without writing keys to a file.

To select one profile directly:

```toml
[egress.aws]
destinations = ["sts.us-east-1.amazonaws.com"]
secret.ref = "aws://bedrock"
```

This uses the SDK's `ProfileFileCredentialsProvider`. Exported keys and `AWS_PROFILE` do not override the selected profile. A role profile can still name the environment or metadata as its credential source. Missing or unusable profiles fail without falling back to another identity. The SDK owns static keys, `credential_process`, SSO, and role resolution. Run:

```sh
python3 crates/box/prototype-aws/run.py profile --profile bedrock
```

Each smoke run makes two STS `GetCallerIdentity` calls from one contained workload. Success requires HTTP 200 for both. The runner creates temporary Box state under `/var/tmp` and removes it afterward. The [verification record](./verification.json) identifies the checked source, binaries, and results. The chain passed with exported credentials, an ADA-backed profile, and a loopback container-credential fixture. The explicit profile path also passed with deliberately incorrect exported keys and a different `AWS_PROFILE`. All four checks used real STS requests and an unusable `CREDSD_SOCKET`.

## Implementation and limits

`prototype_aws_sdk.rs` is the shared adapter. It retains one provider on a dedicated worker for each selected source in a vault. This bridges the asynchronous SDK to the synchronous signer. The default chain resolves once at startup, then for each signed request. Explicit profiles initialize lazily on the first signed request, then resolve on each request. All acquisitions use the existing audit path.

Each resolution, including lazy provider construction, has a 30-second deadline. The caller waits at most 35 seconds for a reply. One request can wait behind an active request; further concurrent requests fail closed. The worker exits when its request channel closes. Invalid fields and expired credentials are refused. Raw provider errors are withheld from Box's error messages.

Box adds no outer credential cache. It retains the SDK providers and their internal state, but does not use the SDK service client's identity cache. Providers can obtain fresh credentials on each request. Environment credentials cannot renew themselves, and changing a parent shell does not change an existing Box process.

Both paths use the SDK's helper runner. On Unix it uses `sh -c` and inherits the trusted host environment. There is no Box-specific executable pin, environment filter, or output limit. A timeout stops waiting for the SDK operation; it does not guarantee termination of a helper or its descendants. SDK internals also do not share all of Box's buffer-wiping rules. These are prototype limits that need review before release.

The custom helper runner, timestamp parser, and profile-file parser are removed. The SDK's profile parsing, precedence, and helper behavior apply to both paths.

Existing endpoint and signing limits still apply. Live checks use only `sts.us-east-1.amazonaws.com` on Linux. They check HTTP status, not the returned identity. Deployment on ECS, EKS, or EC2, SSO, and renewal after actual credential expiry need separate validation.
