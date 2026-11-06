# Claim verification

How to verify each claim on a page before it ships. A wrong claim does more damage than a missing
page: the reader trusts it, and nothing contradicts it until it fails them.

**The code and its tests are the authority.** When a page and the code disagree, the page is wrong.
Report the disagreement. Never change code to agree with a page. `decisions.md` records why the
design is as it is, and where it disagrees with the code, the code is correct.

## What to verify

| Claim | Verify against | Evidence on the page |
|---|---|---|
| A behavior ("the workload cannot read the box directory") | The code, and the test that pins it | Follow the voice guide's citation rules for the page's audience. |
| A design choice ("one policy engine per box, because...") | `docs/design/decisions.md` | A link to the decision anchor |
| A build, test, release, or debug step and its prerequisites | The script, workflow, or configuration that implements the step, and tests for its behavior claims | The command, prerequisites, and expected result. Name source paths and tests when the contributor needs them. |
| A failure's cause or a prerequisite's reason | The code or tooling that enforces it | Explain the cause and the action it requires; a design decision link is needed only for a design choice. |
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
3. Find the test that pins each behavior claim. Apply the
   [voice guide's rules for the page's audience](voice-guide.md) when deciding which evidence
   belongs on the page. If no test pins a new claim, reduce it to what a test pins or report it
   as unpinned (Tier 3). Preserve an unresolved original claim during a wording-only edit.
   These also count as pinned:
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

If required evidence is missing, verification is incomplete. Report the gap before handoff.

- From `docs-writer`: omit unverified additions. For a wording-only rewrite, preserve and flag an
  unresolved original claim. Missing evidence does not prove it is false. Correct or remove an
  original assertion only with evidence or an explicit change to the requested scope. Report
  the symbol and the tier that failed. Keep verification incomplete until the gap is resolved.
- From `docs-audit`: list each one under `### Accuracy issues`, and add a recommended action to
  get the evidence.
