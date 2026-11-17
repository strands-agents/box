# Dogwood 1.0 history validator

This private executable lets Box validate saved policy history with the exact Dogwood 1.0.0
engine and language before converting that history between versions. Operators use
[`box policy migrate-history`](../../docs/user/policy.md#saved-history-requires-migration).
They do not invoke this executable directly.

The helper has an independent Cargo workspace and lockfile. Cargo cannot resolve exact 1.0.0
and 1.1.2 releases of these compatible-major packages in the main workspace. Pin both
`dogwood-local-engine` and `dogwood-language` to `=1.0.0`; pinning the old engine alone allows
a newer language dependency.

## Build and verify

From the repository root, `just build` builds the helper beside Box, and `just check` runs its
format, Clippy, and test gates. To build it directly into the same directory as a debug Box:

```sh
cargo build --locked --manifest-path crates/dogwood-legacy-migration/Cargo.toml --target-dir target
```

Add `--release` when building a release Box. Copy `strands-box-dogwood-1-0-migrate` with the other
Box binaries when installing from source. Release packaging includes it in Linux archives and
signs it with the other helper executables in the macOS bundle.

## Process boundary

The policy library invokes a retained executable identity and checks protocol version 1 and
both Dogwood versions. It supplies bounded policy and schema input or a private scratch
history through standard input. The helper compiles old statements, recovers a scratch
history, or validates a checkpoint with event replay unavailable. It never receives the
original history file.

Box holds the original database lock, compares the validated state, and publishes a conversion
only after validation succeeds. The helper cannot authorize workload operations. Its process
protocol is private to the matching Box build; it is not a general database repair interface.
