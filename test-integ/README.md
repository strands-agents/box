# test-integ/ — deterministic containment suite

Black-box integration tests that drive the real `strands-box` binary and assert
on its output/exit code. Structured so **adding a test case is dropping one
file**.

A standalone crate, deliberately excluded from the workspace in the root
`Cargo.toml`: it drives the *built* binary as a subprocess rather than linking
any crate here, so it must compile after the workspace and must stay out of
`cargo build --workspace --all-targets` (what the unit-test CI leg runs). It
carries its own `Cargo.lock` for the same reason, and inherits the repo's
`rust-toolchain.toml` (edition 2024 needs rustc ≥ 1.85).

## Running it

The suite resolves `strands-box` from `PATH` first, so build the box and put the
release dir in front:

```bash
cargo build -p strands-box -p strands-box-containment --release --features test-support
export PATH="$PWD/target/release:$PATH"
cd test-integ && ./run.sh
```

`strands-box-contain-trampoline` must sit beside `strands-box` — the shared
release dir gives you that. Needs no AWS credentials and no network service.

**`--features test-support` is not optional**, and it is what CI builds with. It adds the
fixtures the MCP and egress cases run beside the box — `box-mcp-fetch-server`,
`box-mcp-call-probe`, and `box-egress-probe`. Without them eight cases fail at setup with
`copy the fetch server onto the operator PATH: … No such file or directory`, which reads as a
containment regression and is a missing binary.

In CI this is `.github/workflows/containment-deterministic.yml`, called from
`ci.yml` so it reports under the single `CI Gate` status. It runs on
`ubuntu-24.04-arm` and `macos-latest` on the plain `pull_request` trigger: the
suite needs no secrets, so a fork PR runs it with a read-only token and no
approval gate is required for safety.

### macOS blocks; Linux is advisory

`continue-on-error` is set per platform:
`continue-on-error: ${{ startsWith(matrix.os, 'ubuntu') }}`.

**`macos-latest` — blocking.** This is the platform the suite was written
against and the only one that binds `file-graft`, so a regression here is a real
defect and stops the merge. No case is quarantined on macOS.

**`ubuntu-24.04-arm` and `ubuntu-latest` — advisory.** Linux containment runs on
aarch64 and x86_64 (`crates/containment/src/facade.rs`), and both legs run the
same cases. They are advisory because no Linux run has a green baseline yet, not
because either platform is expected to fail. Make a leg blocking by deleting the
expression above once it has a green baseline.

The AppArmor question is settled, and it was **not** the blocker. The workflow
clears `kernel.apparmor_restrict_unprivileged_userns` and probes it with
`unshare`, and that demonstrably works — the run logged `before: 1` → `after: 0`
and `unshare(CLONE_NEWUSER): OK`. The step stays because Ubuntu 24.04 restricts
unprivileged user namespaces on both architectures, and the cage needs that
primitive on any Linux.

### A red leg does not notify anyone

Neither leg posts a comment, opens an issue, or sends mail on failure. The
blocking leg fails `CI Gate`, which is visible on the PR; the advisory leg is
visible only by opening the run. In both cases the per-case table is written to
the job summary and the verdict plus logs upload as an artifact.

`CI Gate` is not yet a *required* status check on the `block-main` ruleset, so a
failure is visible but does not yet physically prevent a merge. Adding it is a
repository-settings change and needs admin.

## Add a test case — one file in the right folder

Cases are grouped into folders by category. Create `tests/<category>/<case>.rs`
with a **snake_case** filename (Rust module names can't contain hyphens):

- policy cases → `tests/policy/`
- containment cases → `tests/containment/`
- telemetry cases → `tests/telemetry/`

```rust
// tests/containment/cn_y_05.rs
use strands_det_harness::det_case;

det_case! {
    name: cn_y_05,                 // a snake_case Rust fn name (match the file)
    id:   "CN-Y-05",               // the case id (appears in verdict.json — keep the hyphens)
    // platforms: [Linux],         // optional: a platform-specific case records SKIP elsewhere
    desc: "One-line description of what must be refused",
    run: |b| {
        b.reset_policy();          // or b.apply_policy("<Cedar/Dogwood rules>")
        let r = b.run_mediated("<attack command>; echo RC=$?");   // in the hosted Shell
        r.assert_spawn_denied("<program>");   // the gate refused it, and the journal says so
        r.assert_absent("<what the program prints when it runs>");
    }
}
```

Never `return` early from the body to skip a platform: declare `platforms:` instead.
A body that launches no workload or makes no `RunResult` assertion is recorded as
`ERROR`, and a `SKIP` the case did not declare turns the suite RED — with one explicit, temporary exception: the
compiled allowlist in `src/quarantine.rs` (see `QUARANTINE.md`; currently CN-W-05 and CN-W-06 on linux only) records an
authorized `SKIP` whose note starts with `TEMPORARY QUARANTINE: `; `verdict.json` then carries `coverage_gate: reduced`
and a `quarantine` array so the reduced merge gate is visible.

Then:

```bash
cargo test --test containment cn_y_05   # just yours (editor gutter run-button works too)
./run.sh                                # whole suite -> ~/det-results/verdict.json
```

No registry to edit, no list to append to — `build.rs` scans each category folder
and generates its module list, so dropping the file is enough. Each case runs in
its **own** fresh box (so the suite runs in parallel). Category comes from the
folder (and matches the id prefix: `CN-*` containment, `TL-*` telemetry,
`PO-`/`MO-`/`SH-` policy).

A box directory is not removed when its case ends. Every box's `bin/` aliases are hard links
to one alias image, and macOS Gatekeeper can resolve that image to any of its link names. If
another case has just removed that name, Gatekeeper kills the exec (`Killed: 9`, "Terminating
process due to Gatekeeper rejection" in `log show`). `run.sh` puts the run's boxes under a
fresh `DET_BOX_ROOT` in `~/.det-harness-boxes/` and removes it after the suite. A direct
`cargo test` leaves its boxes in `~/.det-harness-boxes/`; remove that directory when no suite
is running.

### The fixture API (`b: &BoxFixture`)

Two routes lead into the box, and a case must pick the one its enforcement point lives on:

- **Native.** `[agent] command = ["bash"]` resolves on the declared search path to the HOST
  bash, which the box runs natively contained (namespaces/seccomp on Linux, Seatbelt on
  macOS). Its builtins and redirections (`read`, `printf`, `>`) are the agent's own syscalls
  and a program it runs is a plain exec — nothing passes the broker, nothing is journaled.
  Use it for kernel properties: the mount view, the operator-home floor, write-xor-exec,
  environment composition, the future-file deny.
- **Mediated.** The box puts its alias directory first on that bash's PATH, and only an
  explicit alias invocation enters the broker: `zsh -lc …` is the hosted Strands Shell
  (whose `cat`, `ls`, `curl`, `ln`, `echo`, `python3` are Shell commands, journaled as
  `shell:exec`, and whose spawn of anything else is a `shell:spawn` the gate judges), and
  `python3 -c …` is Monty. Use it for policy, spawn-gate, reach-floor and Monty properties.
  This is how the Core suite drives the Shell (`box_shell.rs`: native bash running `zsh -lc`).

`CN-R-01` pins the two routes against each other, so a change in the box's alias layout
fails there first.

| call | route | does |
|---|---|---|
| `b.reset_policy()` | — | restore the pristine deny-by-default baseline |
| `b.apply_policy("<rules>")` | — | compose Cedar/Dogwood rules onto the baseline |
| `b.run_sh("cmd")` | native | run in the contained bash → `RunResult` (prints `DET_ENTERED` first) |
| `b.run_mediated("cmd")` | mediated | native bash runs `zsh -lc` → the hosted Shell echoes `DET_MEDIATED`, then `cmd` |
| `b.run_py("script")` | Monty | native bash runs the `python3` alias with `-c` (the alias accepts nothing else); the script prints `DET_MONTY_ENTERED` first |
| `b.assert_python_is_monty()` | mediated | the identity control for a Monty case: the hosted Shell's `python3 --version` must say Monty |
| `b.run_sh_with_config(edit, "cmd")` / `b.run_mediated_with_config(edit, "cmd")` | native / mediated | the same, against an edited copy of the box configuration |
| `b.compile_probe(name, src)` / `b.with_exec_tree()` | a native probe binary in the exec tree, and the config edit that lets the agent run it |
| `b.journal()` / `b.decisions()` | the box's decision journal, raw or parsed |
| `b.telemetry()` / `b.telemetry_at(path)` | that journal as a parsed `telemetry::Journal` — see **Telemetry** below |
| `b.telemetry_file()` / `b.box_id()` | the default destination, and the `box_id` every record names |
| `b.with_telemetry_file(path, &["deny"])` | the config edit declaring one `file` target, which REPLACES the default destination |

Every `RunResult` carries its `route` and its `decisions`: the policy decisions the box
journaled during that run (action, resource, rule, `permit`/`deny`). Assertions panic on
failure (so a case is ordinary `#[test]`), and every one of them first requires that the
run entered by its route — `DET_ENTERED` from the native bash; for a mediated run also
`DET_MEDIATED` from the Shell and a journaled `shell:exec` for that echo — so a usage
error, a load refusal, a host zsh, or a wrong interpreter is `ERROR`, never a deny:

| call | route | passes when |
|---|---|---|
| `.assert_spawn_denied("prog")` | mediated | the journal holds a `shell:spawn` deny (and no permit) naming `prog` and the Shell printed `effect denied`; the case echoes and asserts the operation's own status (`echo RC=$?` → 126), since the run's exit is that of its last command |
| `.assert_mediated_denied("fs:read", "path")` → rule | mediated / Monty | the journal holds a broker deny for that action on a resource containing `path`; returns the rule (`default-deny`, a policy id, `enforcement:reach-floor`) |
| `.assert_mediated_permitted(action, res)` | mediated / Monty | a permit was journaled — the positive control before a later enforcement point |
| `.assert_monty()` | Monty | the script printed `DET_MONTY_ENTERED`, or Monty signed its exception with "this box's Python is Monty" (a compile-time import rejection prints nothing else) |
| `.assert_kernel_marker()` | native | a kernel refusal spelling is in the output (only meaningful beside an absent effect and, where possible, a host-planted file) |
| `.assert_refused_at_load(&[needles], "MARKER")` | the box refused the configuration at load naming every needle, and the workload never printed `MARKER` |
| `.assert_allow()` | exit 0 and no denial marker |
| `.assert_contains("s")` / `.assert_contains_any(&[..])` / `.assert_absent("s")` | literal output checks |

There is deliberately no bare `assert_deny()`: a nonzero exit is not a refusal. Name
the enforcement point, prove the workload entered, and prove the effect absent —
the program's own output, a host-side file, a socket, a process. Put multiple
assertions in one case when they check one scenario (see `tests/containment/cn_x_02.rs`).

### Cases that need a newer box

There is no per-commit gate. A case that needs a box feature asserts it and names
the requirement in its failure message, so on an older box it reads as a FAIL
with the reason rather than an ERROR. Today `CN-F1-01` needs the box at
`c7d0f41d` or later (follow-up F1: a program under the agent's own `exec` entry
runs with no `[tool.*]` table); on `864df453` the spawn is refused by name and
the case FAILs.

## Layout

| path | role |
|---|---|
| `src/lib.rs` | shared harness + the `det_case!` macro |
| `src/telemetry.rs` | the telemetry file as a reader validates it: lines, records, spans, producers |
| `src/verdict.rs` | per-test JSONL rows + the reducer |
| `src/bin/emit-verdict.rs` | reduces rows → `verdict.json` |
| `build.rs` | scans the category folders, generates their module lists |
| `tests/policy.rs`, `tests/containment.rs`, `tests/telemetry.rs` | aggregator binaries (`include!` the generated lists) |
| `tests/policy/*.rs`, `tests/containment/*.rs`, `tests/telemetry/*.rs` | one file per case (auto-discovered) |
| `tests/probes/*.rs` | native probe sources a case `include_str!`s and compiles with `compile_probe`, and the parser of their output lines a case `include!`s; not cases, and not scanned by `build.rs` |
| `run.sh` | build + test + emit `verdict.json` (CI calls this) |
| `tools/summarize-verdict.py` | renders `verdict.json` into the CI job summary |

## verdict.json (pipeline contract)

`run.sh` writes `$DET_RESULTS_DIR/verdict.json` (default `~/det-results`) with
`platform`, `box_commit`, `verdict` (GREEN/RED), `counts` (`total`, `pass`, `fail`,
`error`, `skip`), `by_category`, `integrity`, and a `results[]` row per case
(`PASS`/`FAIL`/`ERROR`/`SKIP`). Exit code: `0` GREEN, `1` RED.

The reducer is fail-closed. `build.rs` compiles a manifest of every case file's
`id:` and `platforms:`, and GREEN requires all of:

- every manifest case recorded exactly once, with a result in the known vocabulary,
  in the category its folder says; no row for a case that is not in the suite;
- no `FAIL`, no `ERROR`, at least one `PASS`;
- every `SKIP` declared by that case's `platforms:` for this platform (and no
  declared-inapplicable case recorded as anything else);
- no malformed row file;
- `cargo test` exited 0 (`run.sh` passes its status as `DET_CARGO_STATUS`).

Everything else is RED, and `integrity.problems` names each reason, so a filtered
run, a crashed test binary, a build failure, or a run that never happened cannot
reduce to GREEN. `tools/fault-inject.sh` proves this against a fake `strands-box`
(permissive, never-entered, usage error, subset, cargo failure, unreported status)
on any host — it needs no real box and proves nothing about containment, only that
the harness cannot report containment it did not observe.

## Monty

`run_py` runs the script through the box's `python3` alias from the native bash;
the alias forwards to the broker's interpreter, Monty, and accepts only `-c SOURCE`
or a script (no `--version`). A Monty case therefore runs
`b.assert_python_is_monty()` first — the hosted Shell's `python3 --version`, the
supported path for the question — and `assert_monty()` then requires the script's
own sentinel or Monty's exception footer. Monty's file operations are policy-judged
and journaled like the Shell's, so `assert_mediated_denied` applies to them too.

## Telemetry

A `TL-*` case asserts on the FILE the box writes, not on a `RunResult`. `b.telemetry()`
reads the default destination — `<box_dir>/private/telemetry/records.jsonl` — and
`b.telemetry_at(path)` reads a destination the case declared. Parsing is lenient and
the assertions are strict: a line the reader cannot read is a defect in the box, so it
reaches the case as a FAIL rather than stopping the reader.

| call | passes when |
|---|---|
| `.assert_recorded()` | the destination holds at least one request |
| `.assert_well_formed()` | every line is exactly one of `resourceLogs`, `resourceSpans`, `resourceMetrics`, with at least one resource |
| `.assert_identity(box_id, source)` → run ids | every record and span names that `box_id`, that `strands.box.source`, and a non-empty `strands.box.run.id` |
| `.assert_scopes_are_the_boxs_own()` | the file names `strands-box.policy` and `strands-box.control` and no third scope |
| `.assert_decision(action, resource, verdict)` → record | one decision record matches all three |
| `.assert_mediated_entry()` | the file holds the `shell:exec` permit for the Shell's own `echo DET_MEDIATED` |
| `.assert_present(needle, why)` / `.assert_absent(needle, why)` | literal checks over the whole file |
| `record.assert_attribute(key, value)` | that record's attribute holds exactly `value` |

Read `.logs()`, `.spans()`, `.logs_under(scope)`, `.scopes()`, `.sources()`, `.run_ids()`,
and `.decisions()` for anything the assertions do not cover.

**Three things about these cases are easy to get wrong.**

- **The attribute spelled `strands.box.name` holds the box ID, never the authored `name`.**
  Use `b.box_id()`, which reads it out of the stored record.
- **One `strands-box run` is one `strands.box.run.id`.** The fixture preflight is a run of
  its own, so the default destination always names at least two runs.
- **A declared target REPLACES the default destination**, so every `RunResult` assertion on
  a mediated run stops working: each one first requires a journaled `shell:exec` read from
  the default file. A case that declares a target therefore takes the NATIVE route and
  invokes the `zsh` alias itself, then proves entry with `Journal::assert_mediated_entry` on
  the declared file. TL-F-04 and TL-F-05 both do this, and say so.
