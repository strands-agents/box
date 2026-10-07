# TEMPORARY QUARANTINE — cells that record an authorized SKIP instead of running

**Status: ACTIVE. These cases will be re-enabled after the fix is in place.**

| case | platform | body | why | owner | evidence |
|---|---|---|---|---|---|
| CN-W-05 | linux | unchanged, runs only on linux | authors `[tool.git.filesystem] exec`, which a box refuses at load under [the leaf toolchain decision](../docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds); broad exec ships on macOS only, and broad exec for a Linux tool leaf is a currently-missing feature | box-maintainers | recorded on a Linux run |
| CN-W-06 | linux | unchanged, runs only on linux | authors `[tool.cargo.filesystem]` and `[tool.hello.filesystem] exec`, which a box refuses at load under [the leaf toolchain decision](../docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds); broad exec ships on macOS only, and broad exec for a Linux tool leaf is a currently-missing feature | box-maintainers | recorded on a Linux run |

The maintainers approved this exception for the CN-W-05 and CN-W-06 linux cells. Both cases
author a tool `exec` list that a box refuses at load under [the leaf toolchain decision](../docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds), and both
run only on linux. Broad exec ships on macOS only; broad exec for a Linux tool leaf is a currently-missing feature
the team plans to build. This supersedes the no-exclusion rule ONLY for those two linux cells, until that Linux
broad-exec feature lands and the fixtures are aligned to it.

## The mechanism (smallest transparent one the harness supports)

- `test-integ/src/quarantine.rs` holds the **compiled, exact allowlist** `TEMPORARY_QUARANTINE` of
  `(id, platform, reason, issue, owner, restore_when)` and the ONE authorized note text (`quarantine::note`).
  A unit test pins the list to exactly `[("CN-W-05","linux"), ("CN-W-06","linux")]`, so any change is a visible diff.
- **Runner** (`run_case_on` in `lib.rs`): platform declarations (`platforms: […]`) are checked first, unchanged;
  then, if the `(id, current platform)` cell is listed, it writes a `SKIP` row with exactly the authorized note and
  **does not run the body**. On every other platform and for every other case nothing changes.
- **Reducer** (`verdict::Summary::build`): a `SKIP` on an applicable platform is accepted **only** for a listed cell
  **and only** with exactly the authorized note; a listed cell that recorded `PASS`/`FAIL`/`ERROR` is an integrity
  problem (runner and reducer disagree); an unlisted `SKIP`, a wrong or missing reason, a missing or duplicate row,
  a malformed row, a nonzero `cargo test` exit, any other `FAIL`/`ERROR`, and the collector's platform/commit checks
  all remain RED. Runner and reducer read the same compiled list.
- **Report:** `verdict.json` gains `coverage_gate` (`"full"` or `"reduced: N quarantined cell(s) on this
  platform"`) and `quarantine: [{id, platform, reason, issue, owner, restore_when, applied}]`; each SKIP row's note
  starts with `TEMPORARY QUARANTINE: ` and names the case, platform, reason, issue, owner and restoration condition.
  `emit-verdict` prints both. These fields are additive; the collector reads only `verdict`, `platform`,
  `box_commit`, `counts` and `integrity`, so the collector needs no change.

Example (linux, reduced gate):

```json
{
  "platform": "linux", "box_commit": "…", "verdict": "GREEN",
  "counts": { "total": 51, "pass": 41, "fail": 0, "error": 0, "skip": 10 },
  "integrity": { "cargo_status": 0, "expected": 51, "recorded": 51, "problems": [] },
  "coverage_gate": "reduced: 2 quarantined cell(s) on this platform",
  "quarantine": [
    { "id": "CN-W-05", "platform": "linux", "reason": "authors [tool.git.filesystem] exec, …", "issue": "…",
      "owner": "box-maintainers", "restore_when": "broad exec for a Linux tool leaf is built, …", "applied": true },
    { "id": "CN-W-06", "platform": "linux", "reason": "…", "issue": "…", "owner": "box-maintainers", "restore_when": "…", "applied": true }
  ],
  "results": [ …, { "id": "CN-W-05", "result": "SKIP", "note": "TEMPORARY QUARANTINE: CN-W-05 on linux: …" }, … ]
}
```

## Semantics of GREEN while this file is non-empty

- **macOS GREEN = the full merge gate:** no cell is quarantined on macOS, and `coverage_gate` reads `full`.
- **Linux GREEN = the explicitly reduced merge gate:** every applicable cell passed except CN-W-05 and CN-W-06,
  which recorded authorized SKIPs pending broad exec for a Linux tool leaf (a currently-missing feature). It is
  **not** full qualification.
- Global qualification still requires PASS for every applicable cell on both platforms; the exception is only for
  the merge gate.

## How to remove the exception (re-enable)

Edit `TEMPORARY_QUARANTINE` in `test-integ/src/quarantine.rs`, update the pinned test
`the_quarantine_is_exactly_the_authorized_set` to the remaining set, and delete the
"TEMPORARY QUARANTINE" comment block above each re-enabled `det_case!`. The file is RESOLVED (or
deleted) only once `TEMPORARY_QUARANTINE` is empty.

### Linux tool-exec cells (CN-W-05, CN-W-06)

1. Land broad exec for a Linux tool leaf (the currently-missing feature) and align the two fixtures
   to it, so neither authors a `[tool.<name>.filesystem] exec` list a box refuses.
2. Delete the `CN-W-05` and `CN-W-06` entries; update the pinned test; remove the comment blocks
   above those two cases.
3. Run the full deterministic suite on Linux. Both cells must execute and PASS; the linux
   `coverage_gate` must lose these two.

## Verification performed here (Linux host; native macOS runs are not covered here)

- Runner: each listed cell on `PLATFORM=linux` records the authorized SKIP and never runs its body; the same cases on
  `macos` run their bodies; an unlisted case (CN-E-01, CN-E-02, CN-C-01) on macOS runs its body; a `platforms:`
  declaration still wins and keeps its own note.
- Reducer: authorized linux run → GREEN with `coverage_gate` reduced and both entries `applied`; macos → `full`, and a
  quarantine note is rejected on macos; unlisted SKIP with a quarantine-shaped note → RED; wrong/missing/foreign
  reason → RED and `applied: false`; listed cell that ran (PASS/FAIL/ERROR) → RED; missing row, duplicate row, cargo
  101, unreported cargo status, another case's ERROR, malformed row → RED.
- Static/build: `cargo test --lib`, `cargo test --release --no-run` (full case set), `cargo clippy --release
  --all-targets`, `tools/fault-inject.sh permissive` (Linux).
