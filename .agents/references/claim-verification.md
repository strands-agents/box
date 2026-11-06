# Claim verification

How to verify each claim on a page before it ships. A wrong claim does more damage than a missing
page: the reader trusts it, and nothing contradicts it until it fails them.

**The code and its tests are the authority.** When a page and the code disagree, the page is wrong.
Report the disagreement. Never change code to agree with a page. `decisions.md` records why the
design is as it is, and where it disagrees with the code, the code is correct.

## What to verify

| Claim | Verify against | Evidence on the page |
|---|---|---|
| A behavior ("the workload cannot read the box directory") | The code, and the test that pins it | None. The test must exist, and the page does not name it. |
| A reason ("one policy engine per box, because...") | `docs/design/decisions.md` | A link to the decision anchor |
| A `box.toml` key, its type, or its default | The configuration parser in `crates/box/src/` | The example parses and runs |
| A CLI verb, flag, or exit code | The argument parser in `crates/box/src/` | The command runs and gives the stated output |
| A policy action or field | The schema that `strands-box policy generate-schema` prints | The example policy validates |
| A platform difference | Both backends in `crates/containment/` | One statement per platform |
| A binary, its name, or where it is installed | `Cargo.toml` `[[bin]]` entries, the staging step in `.github/workflows/deploy-box-artifact.yml` | The names that ship |

## Procedure

Use the first tier that is available. Go to the next tier only when the one before it is not
available.

### Tier 1: the source in this repository

1. Verify against current `main` (`git show origin/main:<path>`), not the base of the branch the
   page came from. A pull request's base can be days behind, and its claims go stale with it.
2. Read the code that implements the claim.
3. Find the test that pins it. Do not name the test on the page, because a test name is an
   implementation detail. If no test pins the claim, either reduce the claim to what a test pins,
   or report it as unpinned (Tier 3). These also count as pinned:
   - a known defect pinned only by an `#[ignore]` test, for a residual-risk statement;
   - a test in a dependency that Box pins, such as the Dogwood crates, for that dependency's own
     behavior.
4. For a command or a `box.toml` example, run it. Build with `cargo build -p strands-box
   --all-features` and run the release binary. Containment differs per platform, so say which
   platform you ran it on.
5. If a test pins the page itself, run that test after you change the page:
   - `crates/box/tests/documented_commands.rs` pins the verbs in `crates/box/README.md`.
   - `crates/box/tests/documented_inputs.rs` pins the keys in `crates/box/README.md`.
   - `crates/policy/tests/readme_examples.rs` pins the Rust examples in `crates/policy/README.md`.

   Run each with `--all-features`, because some tests sit behind `test-support`.

### Tier 2: run it on the other platform

When a claim is about the platform you are not on, use the `debug-os-failure-on-github` skill to
run the probe or the test on a hosted runner.

### Tier 3: stop and report

If you cannot verify a claim, do not ship it. Do not leave it as a to-do for a reviewer.

- From `docs-writer`: leave out the claim or the example. Report each one beside the draft, with the
  symbol it depends on and the tier that failed.
- From `docs-audit`: list each one under `### Accuracy issues`, and add a recommended action to
  get the evidence.
