# Dogwood 1.0.0 migration fixtures

These two synthetic databases were created by the published Dogwood language and local engine **1.0.0** on Linux ARM64 on November 13, 2026. They test recovery of old saved policy text and preservation of temporal state. They are engine fixtures, not recordings of a complete Box command-line session.

The adjacent `provenance.json` records exact file hashes, crate versions and registry archive checksums, generator hashes, timestamps, and offsets. `generator/` contains the unmodified source, manifest, lockfile, and Rust 1.98.1 toolchain selection used to create the files. It is an isolated manual generator; normal unit tests read the checked-in databases and do not build it.

## Stored policy and history

`authored-policy.dw` and `action-schema.cedarschema` preserve the exact input strings, including leading newlines. `Drupe` is the synthetic fixture namespace. The policy permits Login and Read actions, then forbids Read when the number of matching Login responses in one hour reaches the request's threshold.

The generator installs three policies and the action schema, proves that Read at threshold two is initially allowed, records a Login request and two Login responses, and proves that Read at threshold two is denied. The old renderer stores the static guard as `context has "input".user`. This saved spelling requires explicit compatibility conversion under newer Dogwood parsing.

| Fixture | Base offset | Next offset | Snapshot boundary | Retained records |
| --- | --- | --- | --- | --- |
| `old-complete.redb` | 0 | 10 | None | 10 |
| `old-pruned.redb` | 10 | 11 | 10 | 1 |

The complete fixture does not call `checkpoint`. The pruned fixture calls the actual old engine's `checkpoint`, which writes the snapshot and prunes its covered prefix. It then submits one more denied Read request at offset 10. The resulting database has a genuine snapshot plus a nonempty suffix; no offset padding or fabricated snapshot is used.

The checked-in SHA-256 values are:

```text
6f12465faa3632b98599163080fc2605c8cab38d7b6c654766261522d97f16b3  old-complete.redb
bcfee22497f6b099728b8bb1a87fe9e744c96785994a40a1bdcc3dba17a85b8c  old-pruned.redb
```

## Fixed clock

The fixture clock returns `1800000000000000000` Unix nanoseconds, or January 15, 2027, at 08:00 UTC. This is a synthetic test epoch, not the date the files were generated. The engine advances timestamps by individual nanoseconds while processing events at that fixed clock.

The archived generator uses `Duration::MAX` for its fixture-only future-skew setting. Current storage tests inject the same fixed clock and retain the normal future-skew limit. Production migration uses its normal clock and skew checks. Do not open these dated fixtures with a production wall clock and interpret an expiry or future-time refusal as a migration result.

## Manual regeneration

Run these equivalent commands from this fixtures directory. The output paths are local to a new `generated` directory, so these commands do not overwrite the checked-in files. No nightly toolchain or scheduled regeneration is needed.

```sh
mkdir generated
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 TMPDIR=/tmp \
  cargo +1.98.1 build --locked --manifest-path generator/Cargo.toml --target-dir generated/target
generated/target/debug/p112-recovery-repro seed generated/old-complete.redb complete dotted-has > generated/complete.json
generated/target/debug/p112-recovery-repro seed generated/old-pruned.redb pruned dotted-has > generated/pruned.json
```

These are the original seed arguments with output paths relocated. The archived source also contains diagnostic reopen and transformed-copy modes from the investigation. Those modes did not produce these two input fixtures and are not the production migration implementation.

Regeneration must preserve policy semantics, event counts, checkpoint behavior, and the documented offsets. It need not produce identical database bytes: generated policy tokens and database allocation can differ. Inspect the emitted JSON, validate the resulting files, and update provenance deliberately before replacing fixtures.
