# Upstream provenance

This directory vendors the Rust implementation of Strands Shell from:

- repository: `https://github.com/strands-agents/shell`
- revision: `06169c666260c15422e464a64ad5115ec6e9ac5f`

The nested Git repository, lockfile, build outputs, generated graph, language
packaging, and release tooling are intentionally excluded. `LICENSE` and
`NOTICE` are preserved from upstream.
Each file that differs from the pinned revision starts with a modification notice.
A file that is new in this copy has no notice.

The upstream interactive CLI is feature-gated locally so the embedded library
does not pull its terminal editor into the product. Its optional `rustyline`
constraint is held at 15, which shares the workspace's `unicode-width` version.

## Local divergence from the pinned revision

### Local addition: an effect says which words the script stated (2026-09-25)

At the pinned revision `expand_words` returns `Vec<String>` and discards which `Word` each string came
from, so `EffectAttempt::ShellRun` and `ShellSpawn` present `args` with no provenance. An interceptor
therefore cannot tell `setopt pipefail`, which the submitted script carries, from
`echo $(cat secret.txt)`, whose argument is a file's contents. That matters to an interceptor that
**records** a command: the box writes a decision record an operator may ship to a vendor endpoint, and
[the box's fixed attribute set](../../docs/design/decisions.md#the-policy-attribute-names-are-this-products-own)
excludes the command line for exactly this reason.
Measured before this change, with the values reported verbatim: a read secret appeared twice in the
box's record file.

This is upstream's own gap rather than the box's to work around. The expander **has** the information
and drops it, and no composition above the seam can recover it: by the time an interceptor sees a
`String`, every expansion has already happened.

`parser::word_is_literal` answers it for one `Word` — true when every part is `Literal` or
`SingleQuoted`, recursing through `DoubleQuoted`. `Tilde` and `Arith` are **not** literal, because each
resolves to something the script does not state, so an interceptor judges the result instead.
`exec::expand_words_tracked` carries one flag per produced string, and `expand_words` is now a thin
wrapper over it, so no other caller changed. A literal word marks every string it produces, because
field splitting and globbing both fan one word out and a glob result is a filename the filesystem
supplied.

`ShellRun` and `ShellSpawn` each gain `literal: &'a [bool]`, aligned with `args` by index, and
`Mediated::admit_run` and `admit_spawn` forward it. `admit_pipeline` drops the mask's first entry,
because that one covers the program.

**A rewrite that lengthens a stage must move the mask with it.** The first version of this addition
did not: both `ExecTarget::Shebang` branches replace `expanded_args[i]` with a longer vector — the
interpreter words, and for a multicall the basename and the script path — and left `literal_args[i]`
at its old length. `admit_pipeline` then read `mask.get(1..)` with no alignment check, so a `true`
meant for a later literal word landed on an earlier position. That is worse than over-redaction: a
`$VAR`-expanded secret reaching a script through a `#!` line would be reported verbatim. Both
branches now rebuild the mask beside the words, and each prepended word is `true`, because it comes
from the operator's own `#!` line rather than from the script's argv. Two further lines: a
`debug_assert_eq!` on the two lengths after each rewrite, and `admit_pipeline` dropping a mask whose
length disagrees with its stage — an absent entry already counts as expanded, so a dropped mask
redacts rather than leaks. `ExecTarget::Multicall` needs none of this, because it assigns
`expanded_args[i][0]` and preserves the length.

**There is no regression test, and that is a gap rather than a decision.** `resolve_executable`
returns `None` for a `#!` script reached through a `bind_direct` mount, so the branch did not fire
from a `Shell::builder` harness and a test written against it passed with the defect deliberately
restored. It was deleted rather than kept: a test that cannot fail reads as coverage. Whoever reaches
that branch from a test should pin the alignment there.

**The policy adapter deliberately does not read it.** `crates/policy`'s four destructuring sites ignore
the field: a decision is about what runs, never about how a word was spelled, and reading provenance
there would make the spelling a policy input. Only the record reads it.

`parser::tests::a_word_is_literal_only_when_no_part_expands` pins the predicate over four literal
spellings and eight expanding ones. The suite is unchanged otherwise: 1,294 plus 17 suites, zero
failures, and no new lint.

### Local addition: a host program may be spelled as a path (2026-09-19)

`exec.rs::host_program_path` takes a program spelled with a separator, absolute or relative to the
Shell's working directory, as that path; a bare name still walks the operator's host `PATH`. The
pinned revision refuses every spelling with a separator. Both kinds are named by their canonical
identity when a file exists (`HostProgram::bound`); a spelling that names no file is judged on its
folded spelling and left unbound. The spelling is judged before the host is consulted, so a refusal
discloses nothing about the host. `mediate.rs::CommandPermit` carries the `HostProgram` to
`spawn_host_program`, which no longer resolves the spelling a second time and answers
`command not found` for an unbound one, so a file planted after the decision never reaches the seam.
That second resolution was upstream's own defect: the `EffectAttempt::ShellSpawn::program_path`
contract already states that the exec must use the decided value and never re-resolve. What remains
is the file at a bound path when the kernel execs it, which is whatever is there then; no `PATH`
entry is workload-writable unless the operator granted a write there, and the box discloses a command
or an interpreter inside a writable grant at startup. Closing that last window means carrying an
opened descriptor from the decision to the exec, the fix `tests/kernel_effect_interception.rs`'s
pinned symlink-swap case also wants for paths.
`in_mount_admission_window.rs::a_symlink_swapped_inside_the_admission_window_cannot_divert_a_host_spawn`
and `a_program_planted_inside_the_admission_window_does_not_reach_the_seam` pin it. The box's
allowlist is the resolved identity — the `shell:spawn` decision and the box's spawn seam, which runs
only a program a declared `[tool.<name>]` names — so the spelling adds no authority, and a program
built under a granted tree is otherwise unrunnable.

Two kinds of divergence: three local additions, then six fixes for upstream's own
bugs. See the "Vendored upstreams" section of the root
[`AGENTS.md`](../../AGENTS.md) for the rule that decides which layer owns a
defect.

### Local addition: the effect seam covers the filesystem (2026-08-05)

At the pinned revision `EffectInterceptor` admits one thing — `EffectAttempt`
has a single `ShellCommand` variant, so a permitted command's file reads and
writes reach the `Kernel` unjudged. The box needs a per-path decision, so the
seam was extended locally. This is an **addition, not a fix**: upstream's
narrower seam is not wrong, it is narrower than the box requires.

- **`src/mediate.rs` is new.** `Mediated` holds the `EffectInterceptor` and is
  the only route to a `Kernel`. It resolves each path, presents the effect, then
  acts on the *same* resolved identity. Admission lives here rather than in a
  kernel so that a caller-supplied kernel is governed identically.
  `Mediated::admit_command` and `CommandPermit` replace `Shell`'s
  `intercept_shell_command` and `EffectPermitGuard`, which were deleted.
- **`src/effect.rs` gains two attempt kinds** — `Filesystem` and
  `FilesystemPair` — with `FsOperation`, `FsPairOperation`, `EffectResult`, and
  `EffectOutcome::Kernel`.
- **`src/os.rs` gains `Resolved` and `Follow`.** `Kernel`'s path methods take
  `Resolved`, which only `Kernel::resolve` can mint, so an unresolved path
  cannot reach an effect.
- **`src/vfs_kernel.rs` is reworked** to perform effects and authorize nothing.
  `check_url_safe` and `SafeResolver` live there and stay deny-only.
- **There is deliberately no network attempt kind and no `HttpTransport`
  seam.** `src/os.rs` carries the reason in place of the code: the Shell does
  not authorize egress, so one request yields one decision at the boundary the
  workload is confined to. Two earlier drafts of `AGENTS.md` and `README.md`
  described an `HttpTransport`; no such type ever existed here.
- **Tests:** `tests/kernel_effect_interception.rs` and
  `tests/in_mount_symlink_admission.rs` are new;
  `tests/effect_interceptor.rs` is upstream's and still covers the command
  half.

**On re-vendor this must be re-applied or upstreamed**, otherwise the box loses
every `fs:*` decision. It belongs upstream — the seam is upstream's own API and
one of its two effect classes is missing from it.

### Six fixes for upstream's bugs

All six are upstream's defects rather than local adaptations. **Offer all six
upstream.**

- **`src/exec.rs` (2026-08-09): command substitution evaluated command text without
  presenting it for admission.** `capture_output` parsed `$(…)` / backtick source text and ran
  it through `run_capturing` directly, reaching neither `execute_sourced` nor
  `execute_with_reader` — the two functions where admission lived when this divergence was
  recorded. (It admitted `shell:exec`, which 2026-08-12 replaced with `shell:run` and
  `shell:spawn` on the resolved command.) It is the one
  text-evaluating route that does not funnel through `exec::execute`, which is why moving
  admission down to those two callees did not cover it.

  Upstream's defect on the crate's own contract: `EffectInterceptor` is offered as *the*
  admission seam and one of the crate's own evaluation routes bypasses it. No consumer can
  repair that, because the layer that skips the seam is the layer that owns it.

  **What it did and did not cost, stated precisely — the obvious framing is wrong.** `cmd` is
  the substitution's *unexpanded* source text, so it is always a literal substring of the
  submission the outer gate already judged. This was therefore **not** a text-laundering hole:
  a control payload with the substitution removed (`W=LAUND; X=ERED; printf "${W}${X}"`) leaks
  identically, because admission judges pre-expansion text generally — a separate, documented
  residual of the seam, not of this route. What was actually missing is the **event**: ten
  substitutions in one submission produced *one* `shell:exec` decision where ten through
  `eval`, `xargs`, or `source` produced *eleven*, so a policy counting `shell:exec` or an audit
  reading history saw substitution fan-out as nothing at all.

  Fixed by admitting in `capture_output` before the parse, in the same
  admit-then-report-exactly-once shape as `execute_with_reader`: a `capture_admitted` body split
  so no early return lands between admission and the report, and `run_capturing_status`
  threading the status out of the fork so the permit reports the status the effect actually had
  rather than one read back from the parent.

  Three guards in `tests/kernel_effect_interception.rs`, **each confirmed to fail with the gate
  removed**: `command_substitution_is_admitted_as_its_own_event`,
  `a_denied_command_substitution_does_not_run`, and
  `substitution_fan_out_is_counted_like_every_other_route`. The first matches the **exact**
  admission entry rather than using `contains` — because the inner text is a substring of the
  outer command, a `contains` assertion passes on the outer entry whether or not the
  substitution was ever judged, and two earlier drafts of these tests did exactly that and
  passed against a build with no gate.

  **Second half of the same fix: the capture path reported a status it had not computed.**
  Reporting an outcome required a status, and `run_capturing`'s compound arms — `Item::Group`,
  `Item::Subshell`, `If`, `While`/`Until`, `For`, `Case` — all returned a hardcoded `0`
  regardless of what ran. Harmless while nothing read it; a **wrong outcome in policy temporal
  history** once a permit reports it, which the seam's own contract calls the one thing it
  cannot be wrong about. Measured before the second fix: `X=$(if true; then false; fi)`,
  `X=$( (false) )`, and `X=$( { false; } )` each reported `status=0` to the interceptor while
  the inner command had genuinely failed. Each now threads its real status out through
  `run_capturing_status`, and the same three payloads report `status=1`.

  **One pre-existing status defect is deliberately left**, because it predates this change and
  is not on the admission path: `X=$(exit 42)` reports `127`, not `42` — the capture path has
  no `exit` builtin arm, so `run_pipeline` resolves `exit` as an unknown command. The permit now
  faithfully reports what the shell computed; the shell computes the wrong thing. Fixing that is
  a separate behavioural change to `exit` semantics under capture.

- **`src/exec.rs`, `src/os.rs` (2026-08-09): the single-builtin path discarded an embedder's
  output sink.** `Process::set_channel_writer` is public and `Process::out_msg` checks a
  `ChannelWriter` on `STDOUT` *before* its captured and real-stdout fallbacks — so installing one
  is the crate's own documented way to receive output as it is produced. But `run_pipeline`'s
  single-builtin arm forks an `io_proc` and installs its **own** pipes over `STDOUT` and `STDERR`,
  then drains them either into a captured `String` or to the host's real stdout. A writer the
  caller installed was therefore silently replaced for exactly the commands that arm handles, and
  no output ever reached it.

  Upstream's defect on this repo's own test: the crate offers the API, honours it on the write
  path, and then discards it in one arm — so a consumer cannot repair it, because the layer that
  loses the sink is the one that has it. Note the same arm already carries the caller's *stdin*
  into the fork two lines earlier (`transfer_fd(STDIN, &mut io_proc)`); this is the missing
  stdout/stderr half of that.

  Fixed by adding **`Process::channel_writer(fd)`** — a read accessor beside the existing setter —
  and having the fork inherit an installed writer, falling back to its own pipe when there is
  none. Cloned rather than moved (unlike `transfer_fd`) because a sender is a sink many writers may
  hold, while stdin has exactly one reader.

  Additive by construction: when no writer is installed the pipe-and-drain path is byte-for-byte
  what it was, which is every existing caller. `capture_is_unchanged_when_no_writer_is_installed`
  in `tests/channel_writer_inheritance.rs` is that guard, and it passed *before* the fix — the
  other four tests in that file failed before and pass after, which is what proves the fork was
  the cause rather than `out_msg` or the `capture` flag.

- **`src/exec.rs`, `src/mediate.rs`, `src/shell.rs` (2026-08-08, corrected 2026-08-09): seven
  routes executed command text with no `shell:exec` admission.** Admission lived in `Shell::run`
  and `Shell::execute`, but Lua's `io.popen` and `os.execute`, `find -exec`, `xargs`,
  `sh <file>` / `lash <file>` (via `run_script`), the `.`/`source` builtin, and an `EXIT` trap
  body all reach an evaluator from *inside* the crate and so passed neither. **All seven are
  reachable from an already-admitted command**, so none needed a new grant: one permitted
  command fanned out to N unjudged ones, and an interceptor counting or pattern-matching
  commands saw a single decision.

  This is upstream's defect on this repo's own test — `Shell::run` documents itself as the
  admitted entry point, and a route inside the same crate defeating that contract is not
  something a consumer can repair: an embedder cannot see a nested command at all.
  Measured 2026-08-07 in a real box: a policy permitting only `lua -e *` and
  `printf POPEN_ADMITTED_OK` still executed `printf LAUNDERED_VIA_LUA` and returned its
  output.

  Fixed by moving admission into **`exec::execute_sourced` and `exec::execute_with_reader`** —
  the two functions that actually evaluate text — so every route is judged.

  **`exec::execute` is NOT the right place, and a first attempt that used it shipped an
  incomplete fix.** `run_script` and the `source` builtin call `execute_sourced` directly, and
  the trap calls `execute_with_reader` directly, all bypassing `execute`. Measured 2026-08-09
  against a `forbid` on a marker the outer command never contained: `find -exec` was denied
  while `sh script`, `. script`, and a trap body ran the forbidden text. If you port this,
  gate the two evaluators, not their dispatcher. `Mediated` already owned
  the interceptor and is already threaded through every `exec::execute*`, so no signature
  changed; `Mediated::admit_command` and `CommandPermit` replace `Shell`'s
  `intercept_shell_command`/`EffectPermitGuard`, which were **deleted** rather than left in
  place. Governed by
  [the two-level policy check](../../docs/design/decisions.md#the-shell-checks-policy-at-two-levels) and
  [one admission point after resolution](../../docs/design/decisions.md#one-admission-point-after-resolution).

  Four notes for whoever ports this. `execute_sourced` admits the **whole file content as one
  submission**, never per line — its lines are the content of one piece of submitted text, and
  admitting each would make one `source` cost N budget entries. A nested command is
  deliberately **its own event** —
  `find -exec` over N matches is N admissions plus the outer one — because an interceptor
  must see what actually ran. Do **not** admit in `execute_command_line_inner` instead: it
  recurses for groups, subshells, `if`, `case`, `while`, and `for` bodies, so a
  thousand-iteration loop would emit a thousand events for one command, and it holds a
  parsed `CommandLine` rather than the text a rule matches on. And do **not** re-add a check
  in `Shell::run`: its callee now admits, so a second call double-counts every submission.

- **`src/commands/sleep.rs` (2026-08-08): a sleep cut short by the deadline reported
  success.** `cmd_sleep` correctly races `sleep(duration)` against
  `sleep_until(deadline)` — and then returned `Ok(0)` on either arm, so losing to the
  deadline was indistinguishable from having slept. Under a 30s timeout, `sleep 3600`
  exited **0** after 30s.

  This violates the crate's own documented contract: `Shell::timeout` (`src/shell.rs`)
  says an expired command yields "`status = 1` with `strands-shell: execution timeout
  exceeded` in stderr", which is what `Process::check_limits` returns and what the Lua
  interrupt hook raises. `sleep` was the only place that had the deadline in hand and
  discarded the distinction. Fixed by returning that same error from the deadline arm.

  Found while giving the box's per-request Shell a test for "an expired command is
  reported to its client" — the test failed because the *shell* reported success,
  not because the box mishandled it.

- **`src/exec.rs` (2026-08-07): a failed redirect reported nothing.**
  `run_pipeline`'s single-builtin path calls `set_err_tx` to route `err_msg` into a
  channel, then returns on an `apply_redirects` failure *before* spawning the task
  that drains it — so the message was written into a receiver nobody would read and
  the failure surfaced as a bare non-zero status with empty stderr. Reproduced with a
  read-only bind: `printf x > <ro-path>` was silent, while the identical denial
  through a builtin (`tee`, `mkdir`) printed its reason, because those report through
  a process whose stderr *is* drained. Fixed by calling `clear_err_tx()` before
  reporting, so `err_msg` falls back to the shell's captured stderr.

  Two notes for whoever ports this. `clear_err_tx` already existed on `Process`; only
  the call is new. And do **not** "fix" it by cloning the sender into `set_err_tx`
  instead — that leaves a sender alive on the *success* path, `err_rx` never reaches
  end-of-stream, and every redirect then hangs until the command deadline (measured:
  30s). The success path is what guards this change.

- **`src/effect.rs`, `src/mediate.rs`, `src/exec.rs` (2026-08-12): command admission moved
  from the submitted text to the resolved command.** This is an **orchestration change the box
  owns**, not an upstream defect — upstream is entitled to present whatever it likes for
  admission, and *we* were asking the wrong question. It is recorded here because it changes
  the vendored crate's public `EffectAttempt` surface, so a re-vendor is a merge rather than a
  copy.

  `EffectAttempt::ShellCommand { command }` is replaced by `ShellRun { command, program, args,
  cwd }` and `ShellSpawn { … , program_path }`. `Mediated::admit_command` becomes
  `admit_run` / `admit_spawn` over a shared `admit_resolved`.

  The three admission call sites in `exec.rs` — `execute_sourced`, `execute_with_reader`, and
  `capture_output` — are replaced by **one**, in `run_pipeline`, immediately after the loop
  that resolves each stage's first word. `run_pipeline` is the single function every command
  reaches, so all nine command-text routes are covered by one gate instead of three,
  and each resolved command is its own decision rather than one verdict over a whole
  submission.

  Four things whoever ports this must know:

  1. **Admit every stage before any stage runs.** `admit_pipeline` does the whole pipeline up
     front. Admitting lazily would let stage 1's effect land before stage 2 was refused, so
     `cat secret | curl …` would have already read the file.
  2. **The permit is per stage, and `handles` carries its stage index.** `handles` skips
     word-less stages, so a positional zip against the permit vector reports one command's
     status against another command's permit.
  3. **Three return paths must report**: the single-builtin arm, the single-function arm (both
     of its returns, including the `exit` path), and the pipeline join. A missed path degrades
     to `Indeterminate` from `CommandPermit`'s `Drop` rather than to a hole, which is why the
     failure is quiet.
  4. **Two tests moved with it, and one got stronger.**
     `a_denied_command_substitution_does_not_run` now denies the *expanded* form, which the old
     pre-parse seam explicitly could not see — its own comment recorded that as a residual.
     `substitution_fan_out_is_counted_like_every_other_route` drops from 11 events to 10,
     because the eleventh was the submission and there is no longer a decision over a
     submission. Its parity assertion across `eval` / `source` / `$(…)` is unchanged and is
     the point of the test.

Verified after these changes: `cargo test -p strands-shell --all-features` green (**1770
tests, 1 ignored**), and the crate's clippy warning count **unchanged at 18** — measured
against the untouched checkout in a sibling worktree, since the rule is an unchanged count
rather than zero.

## 2026-08-12 — passthrough execution: a host binary runs after `shell:spawn` admission

**Ours, not an upstream defect.** Upstream is entitled to a shell that implements its own
programs and exits 127 for everything else; the box wants a real `git`. So this is a capability
the box needs, added at the seam upstream already offers, and a re-vendor is a merge rather than
a copy. Governed by
[the policy is the only allowlist](../../docs/design/decisions.md#a-host-binary-runs-in-a-leaf-box-and-the-policy-is-the-only-allowlist).

`admit` (in `exec.rs`) now decides **which action judges a command** before raising it: a `PATH`
lookup that finds a host binary raises `shell:spawn` with its resolved `program_path`, and
everything else raises `shell:run` as before. `admit_spawn` loses its `#[allow(dead_code)]` and
gains its first caller. The external-command dispatch arm tries `spawn_host_program` before
reporting `command not found`.

Four things whoever ports this must know:

1. **`host_path_lookup` walks the HOST filesystem, not the VFS, and that is required rather than
   a shortcut.** `find_in_path` resolves through the Shell's own VFS, where only the box home and
   the declared binds exist — measured, `ls /usr/bin/git` inside the box is "No such file or
   directory" while `PATH` is `/usr/bin:/bin`. So a VFS walk always answers `None` for a host
   binary and passthrough would be unreachable however the policy were written.
2. **127 is kept, not replaced.** Passthrough is tried *before* giving up, so three outcomes stay
   distinguishable: 126 denied, the binary's own status, 127 nowhere on `PATH`. Replacing the arm
   would make an absent program indistinguishable from a refused one.
3. **A builtin is checked before the `PATH` walk.** Otherwise a host binary sharing a name with
   one of the 33 commands would silently turn an operator's `shell:run` rule into a host exec.
   `curl` stays the Shell's own mediated `curl`.
4. **stdio is piped and relayed, never inherited.** Inheriting was measured wrong twice:
   `git --version` returned status 0 while printing nothing to the caller — the bytes went to the
   *daemon's* stdout, which is its log file — and it put a line per command in a log the box
   forbids per-command writes to. stdin is `/dev/null`, so a program cannot read the daemon's
   stdin and one that waits for input cannot hold the Call to its deadline.

**The security property this does NOT have, stated because it is easy to assume:** the binary is
exec'd by the daemon, which sits *outside* the workload's Seatbelt domain, so it is **not
contained**. Measured — `git hash-object ~/.zshrc` returns a hash for a file in the operator's
real home. The only thing bounding it is the `shell:spawn` decision.

Verified after these changes: `cargo test -p strands-shell --all-features` green (**1703 passed,
0 failed, 1 ignored**), and `exec.rs`'s clippy warning count **unchanged at 2** — measured by
stashing these changes and re-running, since the rule is an unchanged count rather than zero.

## 2026-09-10 — passthrough resolves on the operator's host `PATH`

**Ours, not an upstream defect**, and an extension of the passthrough entry above. The box never
set a `PATH` on the hosted Shell, so `proc.env` kept the vendored default `/usr/bin:/bin`.
`shell:spawn` then resolved host binaries against that synthetic value, so `git` at `/usr/bin/git`
worked while a tool under Homebrew, nvm, or mise was reported "command not found" — never resolved,
so never reaching a decision.

`host_path_lookup` now reads the operator's host `PATH` — `std::env::var_os("PATH")`, falling back
to `/usr/bin:/bin` — instead of `proc.env["PATH"]`. It resolves a host binary against the host, so
it searches the host's own `PATH`, for both consumers: the `shell:spawn` decision (`admit`) and the
resolved path handed to the `spawn_host` seam (`HostSpawn.program`). The `proc` parameter is
dropped, since it was read only for that value.

**Why this widens no boundary.** A wider resolution `PATH` changes only *where* a permitted program
is found, never *whether* an unpermitted one runs — the `shell:spawn` decision is the allowlist. The
workload-visible `proc.env` is left synthetic, so `$PATH` inside the Shell does not disclose the
operator's real paths to the agent. Same source and idiom the box's `RunningMcpServer::start`
already uses for an MCP child.

**Scope — resolution only.** The child's runtime `PATH` is not set here. In the box a host binary
runs in a contained leaf, whose environment `Boundary::assemble_leaf` recomposes (the seam ignores
`HostSpawn.env`), so giving a tool the `PATH` to find its own helpers (`npm`→`node`) is a leaf
`compose` change bounded to the leaf's granted toolchain — deferred to a later change. This change makes
the decision name the right program; running a non-toolchain tool contained waits on that grant.

**One test changed with the contract.** `host_program_runs_in_its_own_session` used
`Shell::builder().env("PATH", …)` to steer passthrough resolution to a temp probe. That no longer
steers resolution, so the probe now goes into the first writable directory already on the host
`PATH`, and the test skips when none is writable — an environment-dependent skip, not a failure.

Verified after these changes: `cargo test -p strands-shell --all-features` green (**1831 passed,
0 failed**), and `exec.rs`'s clippy warning count **unchanged at 2**, measured with
`--all-targets --all-features`.

## 2026-08-14 — `in_mount_symlink_admission` read the host before the write reached it

`an_in_mount_symlink_write_lands_on_the_target` was flaky, and the build fleet is what
made it visible: it failed there while passing locally, then reproduced here at **2
failures in 15 runs** with the default test threads and **0 in 10** with
`--test-threads=1`.

`Shell::run` returns status 0 for `printf PWNED > /workspace/sub/flink` before the
redirect's bytes have necessarily reached the host file, so the test's host read raced
the write. One failure observed the target **truncated and empty** rather than holding
either the old or the new value, which is what identified the cause — a lost race, not a
wrong path.

The fix is one line in the test: `run_until` drives only the future it is given, so the
test now awaits the `LocalSet` itself, which drains every task the write spawned.

**The underlying behaviour is a defect and is NOT fixed here.** A command that reports
success and whose write is not yet durable is upstream's to answer, and a box hosting
that Shell inherits it: a Call can complete while its file effect is still in flight.
Recorded rather than repaired, because closing it changes the vendored crate's execution
model and this change exists to unblock a build. Do not "fix" the flake with
`--test-threads=1` — that hides this test and leaves the next one exposed.

**2026-09-09 — the deferred write also defeats the admission-window binding, for the same
reason.** The [admission-window object binding](../../docs/design/decisions.md#a-resolved-token-binds-the-object-it-names)
checks a host object's `(dev,ino)` at `open` time, but this deferred write flushes with
`tokio::fs::write(&path)` **by path string**, later, when the channel closes. So the check and
the disk write are not one act: a directory symlink swapped after `open` returns but before the
flush diverts the write, and for a write-create — where the binding pins the parent because the
leaf does not exist yet — a `leaf` created as a symlink before the flush is followed by
`tokio::fs::write` and can leave the bind. This window spans the whole fd lifetime, wider than
the box's in-memory close (which is atomic under one lock) and wider than the synchronous host
effects' stat-to-syscall gap. It is the **same** upstream deferred-write defect above, now with a
security consequence, and it has the same fix: bind the write to the object opened at
admission — an fd opened under the canonical parent with `O_NOFOLLOW` (Linux `openat2` with
`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`), written into rather than a path re-followed at
flush. That changes the execution model, so it stays a tracked follow-up, offered upstream.

**Where the admission-window binding belongs on re-vendor — box-local, like the host refusals.**
The "Local addition" note above says the effect *seam* belongs upstream, and it does: the `Kernel`
trait, `mediate.rs`, and the `Resolved`/`Follow` types are generic mediation any embedder needs.
The **binding and its refusals** (`Resolved::binding`/`ObjectIdentity`, `verify_host_binding`,
`refuse_if_moved`/`refuse_if_parent_moved`, the canonical-parent create) are a
different thing: a **security control for an adversarial embedding**, where an untrusted workload
races the trusted shell. Upstream also serves a trusting interactive user, for whom these add a
per-effect `stat` and change error semantics — an ordinary missing-parent write becomes
`PermissionDenied`, a symlinked parent is collapsed — for a threat that user does not have. So,
exactly like the
[host-effect refusals](../../docs/design/decisions.md#host-backed-effects-refuse-what-a-write-cannot-produce),
they are **not upstream-worthy in this shape**: offer them only behind an opt-in the embedder
sets (for example, enforced only when an `EffectInterceptor` is installed), never as
unconditional default behavior. On un-vendor, the generic effect *seam* is
offered upstream (and, if adopted, comes from there); the **binding** — and the box's own decision
to install a policy interceptor and supply a `Kernel` that performs effects on the identity it
approved — **stays in the box**. That is the shape the Monty integration already uses (Monty
performs no I/O; the box answers each suspension on the approved path). Do **not** push the binding
upstream as default; keep it with the box's kernel. The lone unconditionally-upstream-worthy piece
is the one-lock mint, which is pure internal consistency with no success-path behavior change.

Verified after this change: `cargo test -p strands-shell --all-features` green (**1770
passed, 0 failed**), the crate's clippy warning count **unchanged at 18**, and the test
itself **0 failures in 60 runs** against 2 in 15 before.

## 2026-08-18 — `bind_direct_write_back` shared process-global test state

The test used the fixed host directory `/tmp/lsh_bind_write_test`, ignored setup
errors, and removed that directory when it finished. Concurrent test processes could
therefore remove another process's bind root while its asynchronous write-back was in
flight. The build fleet failed this test twice with empty host content; locally, **46
of 50** concurrent test processes failed with the same output.

The fixture now includes the process ID in its directory name, checks setup and cleanup
errors, and drains the `LocalSet` instead of guessing that write-back completed after a
50 ms sleep. This is a test-isolation fix only. The underlying behavior remains the
upstream defect recorded above: `Shell::run` may report success before a bind-direct
write reaches the host.

## 2026-08-28 — the timeout reset test had a sub-second command budget

`timeout_is_per_command_not_cumulative` gave `echo ok` 500 ms to finish. Coverage
instrumentation exceeded that budget on the build fleet, so the test reported an
execution timeout after it had already proved that the deadline reset. The test now
uses a five-second command budget and sleeps for six seconds before the command. This
changes only the test timing and keeps the same regression condition.


## 2026-08-20 — additive: `ShellBuilder::egress_proxy` routes outbound HTTP through a proxy

A new, additive local change — not a bug fix. `ShellBuilder::egress_proxy(target, ca_path)`
and a `VfsKernel::egress_proxy: Option<EgressProxy>` field let an embedder route the Shell's
outbound HTTP through an egress proxy instead of dialing origins directly. When set,
`VfsKernel::http_request_effect` builds its `reqwest::Client` with `.proxy(..)` and trusts
**only** the proxy's CA — `.tls_built_in_root_certs(false)` drops the built-in WebPKI roots,
so the client validates the proxy's forged leaves and nothing else. `egress_proxy` also
validates the CA at configuration time (it builds a throwaway client, because
`Certificate::from_pem` is lazy and does not parse the DER), so a malformed CA fails the
builder rather than every request. When unset, the direct-client behaviour with the
SSRF-aware `SafeResolver` and the default root store is unchanged. The SSRF floor
(`check_url_effect`) still runs before any transport either way.

`ShellBuilder::egress_proxy_pem(target, ca_pem)` is the descriptor-safe form. It accepts bytes
that the embedder already read from an approved file identity, and `egress_proxy` delegates to it
after its path read.

This exists so `strands-box` can route the hosted Shell's egress through its one governed
boundary rather than adding a second network authority inside the Shell
([egress decision](../../docs/design/decisions.md#shell-network-goes-through-the-egress-gateway)). It is
plausibly upstream-worthy — proxy support is a general sandbox feature — rather than
divergence for local convenience, and it changes no existing behaviour when the option is
absent.


## 2026-08-20 — additive: `Kernel::run_script` forwards a script to an embedder interpreter

A new, additive local change — not a bug fix, and the sibling of the `egress_proxy` addition
above. It lets an embedder forward a script to an out-of-Shell interpreter:

- **`src/os.rs`** gains `Kernel::run_script(source) -> ScriptOutcome` (default `Unsupported`),
  a `ScriptOutcome { status, stdout, stderr }` type (the mirror of `HttpResponse`), and a
  `ScriptInterpreter` hook type (the script counterpart of `EgressProxy`).
- **`src/vfs_kernel.rs`** gains `VfsKernel::script_interpreter: Option<ScriptInterpreter>`;
  `run_script` forwards to the hook when set, else returns `Unsupported`.
- **`src/shell.rs`** gains `ShellBuilder::script_interpreter(hook)`, a stated position
  mirroring `egress_proxy`.
- **`src/mediate.rs`** gains `Mediated::run_script`, a bare passthrough that raises no
  admission — matching `http_request`, because the command-level `shell:exec` fired at
  resolution and the script's own effects are judged by the interpreter the hook drives.
- **`src/commands/python.rs`** is new: a `python`/`python3` command accepting `-c SOURCE` or
  one script file. A file argument is read through the mediated `fs:read` (a governed read
  that reaches binds), then the source is forwarded through `os.run_script`. It reads no
  stdin, so a no-`-c`, no-file invocation (a REPL, pipe, or heredoc) refuses loudly rather
  than dropping stdin. `--version` reports Monty, never a CPython version.

When no hook is installed, `run_script` is `Unsupported` and the `python` command refuses —
unchanged behaviour for every existing embedder. This exists so `strands-box` can route a
Shell `python` to its Monty interpreter rather than exiting 127
([Monty in the Shell](../../docs/design/decisions.md#python-in-the-shell-is-monty)). Plausibly
upstream-worthy — a scripted-interpreter seam is a general sandbox feature — and it changes
nothing when the hook is absent.

## 2026-09-01 — additive: a guard pins the kernel-seam `Follow` dispositions

A new, test-only local addition to the effect seam (2026-08-05 above). Each `Kernel` effect
asserts its token's `Follow` disposition with a `debug_assert_eq!` and then re-resolves the path
with its own hardcoded follow value, so a `Mediated` site that resolves with the wrong `Follow`
would admit one identity and act on another — a symlink-laundering hole. That assertion is compiled
out in release, leaving the correctness of the 16 hand-wired dispositions unguarded there.

- **`src/mediate.rs`** gains `#[cfg(test)] mod disposition_guard`: one test that exercises every
  `Mediated` operation, tripping the effect's `debug_assert_eq!` in the debug build tests run if any
  disposition is miswired. Proven to fire on a planted flip and restore green.

No production code changed. Plausibly upstream-worthy — it guards upstream's own seam invariant.

## 2026-09-04 — host-spawned programs detach into a new session

**Ours, not an upstream defect.** Upstream is entitled to leave session detach to the embedder,
because only a hosting layer knows whether the parent has a controlling terminal to protect. This
is a local behaviour the box needs, added at the seam upstream already offers
(`Command::pre_exec` on Unix), so a re-vendor is a merge rather than a copy.

`spawn_host_program` (in `src/exec.rs`) now calls `libc::setsid()` through `pre_exec` on Unix, so
a child that opens `/dev/tty` fails locally rather than delivering `SIGTTIN` to the box's process
group and suspending the whole box. `libc = "0.2"` is added under
`[target.'cfg(unix)'.dependencies]`.

Pinned by `host_program_runs_in_its_own_session` in `tests/shell_integration.rs`, which asserts
`sid == pid` (the child is its own session leader) and `sid != parent_sid` (the child left the
parent's session). The test is interpreter-dependent: it resolves a host `python3` for its probe
and skips when none is present.

**Not upstream-worthy in this shape.** The detach is unconditional on Unix, which suits the box
because the box is never interactive. Upstream also serves interactive CLI use, where a spawned
program should keep the controlling terminal so it can prompt, so an unconditional `setsid` there
would regress that path. Upstream would want an opt-in flag (for example
`ShellBuilder::detach_session`), which this change does not add.

## 2026-09-08 — `symlink`, `readlink`, and `chmod` were not host-backed

An upstream bug fix in the vendored kernel. `VfsKernel` host-backs every filesystem effect on a
`bind_direct` path — lock the VFS, `resolve_host`, act on the real disk via `std::fs` — except
`symlink_effect`, `read_link_effect`, and `set_permissions_effect`, which went straight to the
in-memory VFS. The in-memory VFS holds only the mount nodes, not the workload's real files, so
`ln -s`, `readlink`, and `chmod` failed with `ENOTDIR` on any host bind — and `chmod` reported
success while the host file's mode never changed.

Fixed by mirroring the sibling effects' host branch: each now dispatches host-backed paths to the
real filesystem and refuses a read-only bind. `read_link` resolves the *parent* to its host
directory and reads the leaf there, so it reads the link itself rather than following it. This half
is upstream's defect on its own contract — the kernel host-backs the other effects — and belongs
upstream.

**Box-specific, keep local (chmod authority bits):** the `chmod` host branch also refuses
`setuid`/`setgid`/`sticky` (`mode & 0o7000`). The Shell runs in the box's trusted `run` process,
outside the OS cage, on inodes a writable bind shares with the operator's real filesystem; a
set-user-ID bit set there is honoured by a process outside the box. `write` cannot set such a bit,
`chmod` can, so the host branch refuses it (an error, not a silent strip). The in-memory VFS branch
is unchanged (still `mode & 0o7777`): it has no real inode and the existing `test_sticky_bit` relies
on it. `parse_symbolic_mode` seeds its result from `current & 0o777`, dropping any special bit the
file already carries, so an ordinary `chmod +x` on a file that already has `g+s` succeeds rather
than tripping the refusal on a bit the caller never named. A symbolic clause cannot name a special
bit (the perms parser accepts only `r`/`w`/`x`), so only an octal `chmod 4755` reaches the refusal.

**Box-specific, keep local (symlink target floor):** `symlink_effect` stores its target verbatim,
and a process outside the box follows it on the operator-shared inode, so the host branch refuses a
target that is absolute or that escapes the bind — the same "effect honoured outside the box on a
shared inode" hazard as the chmod authority bits. The target is resolved against the link's host
directory and held to the `starts_with(canon_base)` floor `resolve_host` already applies to every
followed path; a target that stays inside the bind is created as before.

**Does not close the open re-resolved-path race.** These effects act on the path `resolve_host`
re-resolves from the caller's string at effect time; host-backing `symlink` (a write) adds one
instance to that pre-existing race class rather than closing or worsening it. The target floor
checks the resolved target and the create is a separate call, so a swapped component between them
stays in that same class.

**Upstream-worthy in halves.** The host-backing belongs upstream — offer it: the kernel host-backs
the sibling effects and these three are the omission, so a re-vendor should merge the fix rather
than re-apply it. The two refusals are **not** upstream-worthy in this shape. Upstream also serves
an interactive shell on the operator's own filesystem, where a `chmod 4755` or an `ln -s /abs/path`
is ordinary and refusing it would regress that path; they guard a hazard specific to the box — an
effect on an operator-shared inode honoured by a process outside the cage — so they stay box-local.
Upstream would want them behind an opt-in the embedder sets, which this change does not add.

Pinned by `tests/in_mount_symlink_ops.rs` (12 cases, including `chmod 4755` refused with no
`0o7000` bit left on the host inode, `chmod +x` on a `g+s` file succeeding, `ln -s` to an absolute
or bind-escaping target refused with no host link planted, `ln -s` to an in-bind target whose
directories do not exist yet allowed, and the target floor failing closed on a non-`NotFound`
`canonicalize` error).

Verified after these changes: `cargo test -p strands-shell --all-features` green, and the crate's
clippy warning count **unchanged at 18**.

## 2026-09-09 — additive: `Kernel::spawn_host` seam for a host binary

A host binary the Shell does not implement is run through a new `Kernel::spawn_host(HostSpawn) ->
HostSpawnOutcome` seam, the host-binary counterpart of `run_script`
([spawn seam decision](../../docs/design/decisions.md#the-box-runs-a-host-binary-through-the-spawn-host-seam)). The types
(`HostSpawn`, `HostSpawnOutcome`, `HostSpawner`, `HostSpawnFuture`), the `ShellBuilder::host_spawner`
setter, the `VfsKernel::host_spawner` field, and `Mediated::spawn_host` mirror the script seam. The
built-in `fork`+`exec` moved from `spawn_host_program` into `os::builtin_spawn_host` (**which was
the seam's default until 2026-09-10 — see the fail-closed entry below**); `spawn_host_program` now
hands the resolved program, args, cwd, and composed env to `Mediated::spawn_host` and relays the
captured output on the Shell's own streams.

**Additive, so upstream-worthy.** The box installs the hook to run the binary inside a contained
leaf box. A re-vendor should merge the seam.

Verified: `cargo test -p strands-shell --all-features` green (1293 + 96 + 13), and the crate's
clippy warning count **unchanged at 18**.

## 2026-09-10 — `spawn_host` fails closed: no hook means refuse, not run uncontained

**Ours** — the `spawn_host` seam and `builtin_spawn_host` are our additions (upstream
`strands-agents/shell` has neither), so this shapes our own code. `Kernel::spawn_host` and
`VfsKernel::spawn_host` now default to `io::ErrorKind::Unsupported`, mirroring `run_script`: with no
`HostSpawner` hook there is no contained path, so a host binary is **refused** rather than run with
`os::builtin_spawn_host` in the trusted process. Containment becomes a property of construction — a
Shell that never wired the hook cannot silently run a program on the host — which closes the
Tenet-1 fail-open finding on the seam default.

`builtin_spawn_host` stays a `pub` function an embedder installs **explicitly** to opt into
uncontained `fork`+`exec`; nothing installs it by default. `host_program_runs_in_its_own_session`
(which measures the built-in's session detachment) now installs it as an explicit hook, and
`a_host_binary_is_refused_when_no_spawn_hook_is_installed` pins the fail-closed refusal.

Verified: `cargo test -p strands-shell --all-features` green (**1832 passed, 0 failed**), and the
crate's clippy warning count **unchanged at 18**.

## 2026-09-12 — Resolved paths did not stay bound through admission

An upstream security bug fix in the effect seam. `Resolved` held only a path string. A background
effect could change a missing component into a symbolic link while the interceptor waited, and the
later effect resolved the same string to another object.

`Resolved` now carries the kernel namespace generation and the host identity observed during
resolution. Each effect validates both values while it holds the same kernel guard through the
operation. Namespace-changing effects advance the generation. The previously ignored
`a_background_symlink_swap_cannot_beat_the_admission_window` test now runs and proves that the
protected file stays unchanged.

Unix host effects now use the admitted identity after this validation. A deferred write keeps the
opened file descriptor until it flushes. Namespace effects use verified parent directory
descriptors, and `chmod` uses the opened object. The
`a_deferred_host_write_stays_on_the_admitted_inode` test replaces the approved pathname after open
and proves that the replacement stays unchanged. Other Unix targets return `Unsupported` from the
descriptor-bound `chmod` helper instead of compiling a body that names platform-only flags.

The same review found that the host symbolic-link target floor treated a dangling symbolic-link
prefix as an absent directory. It now walks each component and refuses a symbolic link whose target
cannot be resolved inside the bind. `ln_s_through_a_dangling_symlink_prefix_is_refused` pins this
case, while `ln_s_to_an_in_bind_target_with_missing_dirs_is_allowed` keeps an ordinary missing tail
valid.

Both defects belong upstream. They are wrong results inside the kernel and effect-seam contracts,
and a consumer cannot repair them after the effect runs.

## 2026-09-15 — the host-effect `openat` mode argument is a `c_uint`, so the crate builds on macOS

The host-effect resolver this fork adds passes an `openat` mode as `libc::mode_t`. On macOS
`mode_t` is `u16`, which a C variadic call must promote, so the `libc` binding refuses it with
`error[E0617]: can't pass u16 to variadic function`. The mode literal in `VfsKernel` now casts to
`libc::c_uint`, the promoted type the call needs, so `strands-shell` builds on macOS. On Linux
`mode_t` is already `u32` and equal to `c_uint`, so the cast changes nothing there.

This is a portability fix to code this fork already carries, not an upstream defect — it keeps the
existing host-effect divergence compiling on both platforms.

## 2026-09-17 — `rm -f` discarded a refused delete, and `rm -r` lost the refused path

An upstream bug in the `rm` builtin. `-f` glued `&& !force` onto both removal calls, so the command
discarded every error a removal returned, not only the nonexistent operand that `-f` exists to
ignore. Through this fork's effect seam a removal returns `Err` on a policy `fs:delete` refusal, so
`rm -f` on a refused path exited `0` and printed nothing while the file survived. The shipped init
policy template forbids `fs:delete`, so the one refusal the default box makes was the one swallowed.

`-f` no longer suppresses a removal error. The nonexistent operand it exists for is still ignored,
because the earlier `lstat` decides that case before the removal, so `rm -f` on an absent path still
exits `0`.

`remove_recursive` now returns whether every removal under a path succeeded, reports each failure by
its own path, and continues to the siblings before it removes the directory. A refused child is
named by its own path rather than its parent's, and the directory reaches a `remove_dir` decision
even when a child is refused, so an audit for the directory's deletion finds a record.

`rm_force_on_denied_path_reports_and_fails`, `rm_recursive_denied_child_is_named_by_its_own_path`,
and `rm_recursive_directory_itself_reaches_a_decision` in `tests/lua_policy_admission.rs` each fail
against the prior code and pass after the change. `rm_force_on_absent_path_succeeds` keeps the
nonexistent-operand exit at `0`; it is a regression guard that passes with or without the change.

Two consequences are deliberate. When a child is refused and the directory delete is permitted, the
directory removal then fails because the tree is not empty, so the operator sees the child refusal
and a following "directory not empty" line; both name the correct path, and the audit record for the
directory is the reason recursion no longer stops before it. A denial on `list_dir` for a nested
subdirectory, which is an `fs:enumerate` decision rather than an `fs:delete` one, still stops the
recursion and is reported against the top path; this route predates the change.

The defect belongs upstream. `rm -f` that suppresses a real removal failure, not only a nonexistent
operand, is a wrong result in the builtin against POSIX; the effect seam makes the swallowed refusal
security-relevant here. Offer it upstream.

## 2026-09-18 — `curl -w` was dropped whenever `-o` was given

An upstream bug in the `curl` builtin. The stdout handle `out` is `Some` only when `-o`/`--output`
is absent; the `-w`/`--write-out` block wrote to that same `out`, so `-o` suppressed `-w` as well.
Real curl sends `-o` the body alone and `-w` to stdout regardless, so
`curl -s -o /dev/null -w '%{http_code}' URL` printed nothing here.

The consequence is larger than the flag. It removed the one status-probe a script uses to tell a
refused request from a success — the workaround for the egress refused-request defect, where a
policy 403 arrives as the body with exit 0.

Fixed in `src/commands/curl.rs`: the `-w` block writes to `out` when present and takes stdout itself
when `-o` nulled it, so the body still goes to the file and `-w` still reaches stdout. The body
write is unchanged, so `-o` still redirects the body alone.

`write_out_reaches_stdout_when_output_goes_to_a_file` in `tests/egress_proxy.rs` pins it: it fails
against the prior code and passes after, asserting `-w` reaches stdout and the body does not.

The defect belongs upstream — a `-w` suppressed by `-o` is a wrong result against curl's documented
behaviour. Offered upstream in [strands-agents/shell#131](https://github.com/strands-agents/shell/pull/131);
the 2026-10-05 entry below carries that version, which replaces this one.

## 2026-09-17 — the SSRF floor refused `localhost` but not `localhost.`

**Ours, not an upstream defect.** `check_url_safe` is a box-local deny-only floor added with the
effect seam above; it is not upstream code. The floor compared the parsed host with a raw string
test — `d == "localhost" || d.ends_with(".localhost")` — so `http://localhost./` (the FQDN root-dot
spelling) and an uppercase spelling matched neither branch. Standard resolvers map these names to
127.0.0.1, so a contained workload reached the operator loopback. The floor is the only loopback
guard on the fetch path, and the Shell `curl` path and the Monty `fetch` path share this one
function, so both were open. A penetration test and a static scan found this.

The `url::Host::Domain` arm now normalizes the host before the test: it trims trailing root dots and
lowercases with `d.trim_end_matches('.').to_ascii_lowercase()`, then compares. This is the same
normalization the egress gateway's `normalize_host` already applies
(`egress-gateway/src/capability/floor.rs`), so the two floors no longer disagree on a spelling.

Pinned by `check_url_safe_blocks_ipv4_and_localhost` in `src/vfs_kernel.rs`, extended with
`http://localhost./`, `http://x.localhost./`, `http://LOCALHOST/`, and `http://LocalHost./`; each
fails against the prior code and passes after the change. `check_url_safe_allows_public_hosts` keeps
an ordinary host allowed, so the change over-blocks nothing.

**Not upstream-worthy.** The floor is a box-local security control for an adversarial embedding, so
it stays with the box, like the other deny-only additions above.

Verified after this change: `cargo test -p strands-shell --all-features` green, and the crate's
clippy warning count **unchanged at 18** in `src/`.

## 2026-09-20 — `HostSpawn` carried the identity but dropped the spelling, so a venv interpreter lost its prefix

**Upstream's own defect, and a wrong result rather than a policy question.** `HostProgram` named a
program by its canonical identity, which is right for the decision, for selection, and for
credentials — and then `spawn_host_program` handed that identity to the seam as the only path. A
workload invoking `.venv/bin/python` ran `/usr/bin/python3.9` with `argv[0] = /usr/bin/python3.9`, so
CPython's own prefix search found no `pyvenv.cfg` and reported `sys.prefix = /usr`. The virtualenv the
caller named was silently discarded. Every interpreter that derives its environment from `argv[0]`
loses it the same way: a Node version-manager shim and a `rustup` shim both do.

`HostProgram` now carries `spelling` beside `path`, and `HostSpawn` carries `invoked` beside
`program`. The identity is unchanged and is still what the decision judges and what the kernel execs;
the spelling is what the program reads as `argv[0]`. `os::builtin_spawn_host` sets it with
`CommandExt::arg0`. `a_symlink_spelling_names_its_target` and
`a_bare_name_is_named_by_its_canonical_identity` now pin both halves, so an identity can no longer be
carried without its spelling.

`tests/host_spawn_argument_zero.rs::the_builtin_spawn_gives_the_program_its_invoked_spelling` runs a real
program through `builtin_spawn_host` and asks it what `$0` is, so the `arg0` call cannot be dropped
silently.

**Additive on the seam, so upstream-worthy — but breaking for a constructor.** `HostSpawn` has all
public fields and no `#[non_exhaustive]`, so adding `invoked` is additive for code that reads one and
breaking for code that builds one; a re-vendor should expect to touch every construction site, as this
change did. A re-vendor should merge the field and the `arg0` call.

## 2026-09-20 — a proxy's own refusal reached a command as a response, so a denied request exited 0

**Upstream's own defect, and a wrong result rather than a policy question.** `EgressProxy` routes
every outbound request through an embedder's proxy, and that proxy intercepts TLS — it presents a leaf
it forged for the origin. A refusal the proxy synthesises inside its own tunnel therefore arrives at
`http_request_effect` as an ordinary HTTP status, indistinguishable from the origin answering with the
same one. `curl` exits `0` for any status without `-f`, which is correct for an origin's `403` and
wrong for the proxy's refusal, so a caller reading the status saw success for a request that never
left the box. The crate offered no way to tell the two apart, and `curl`'s own `PermissionDenied` arm —
which already prints one line and exits `1` — could never fire for this case.

`EgressProxy` gains `refusal_header: Option<String>`, set through the new
`ShellBuilder::egress_refusal_header`, naming the response header the proxy puts on a refusal it
originates itself. `VfsKernel::http_request_effect` checks it **before building the response** and
returns `io::ErrorKind::PermissionDenied` with the first line of the body as the reason, so every
network builtin maps it to the status it already uses for a denial and no builtin can render the
header. `None` keeps the pinned revision's behaviour exactly, so this is opt-in: an embedder with no
intercepting proxy is unaffected.

`tests/egress_proxy.rs::a_gateway_refusal_exits_non_zero_and_is_not_rendered` pins the refusal,
`an_unmarked_403_stays_the_origins_answer` pins that an origin's `403` keeps `curl`'s semantics and its
body, `a_permitted_response_is_unaffected_by_the_marker_check` pins a `200`, and
`without_a_named_marker_the_response_is_unchanged` pins the opt-in. Removing the kernel check fails
the first and passes the rest.

**Additive, so upstream-worthy — and breaking for a constructor.** `EgressProxy` has public fields and
no `#[non_exhaustive]`, like `HostSpawn` above, so a re-vendor should expect to touch its construction
sites. A re-vendor should merge the field, the setter, and the kernel check.

## 2026-09-21 — the `PATH` walk raised one admission for each candidate

**Ours, a fix to the effect-seam addition above (2026-08-05), and not upstream code.** The pinned
revision's `find_in_path` consults the kernel and admits nothing. The seam addition routed each
candidate through `Mediated::is_executable`, which resolves the candidate, presents it as
`FsOperation::Exec`, and records the outcome. For a name found in the third `PATH` entry, or on the
host `PATH` and not in the VFS at all, that is one recorded decision for each directory that did not
hold the name. In one measured run 276 of 297 recorded denials were these probes, so a real refusal
was hard to find, and every probe entered the one temporal history, so an `fs:read` count in a
`when temporal` rule counted directory walks the workload never asked for.

`FsOperation` gains `Locate`: the question whether a `PATH` candidate is an executable file.
`Mediated::find_in_path` now owns the walk. It presents each candidate as `Locate` through the seam,
asks the kernel, and reports the answer on that permit. The first candidate the kernel calls
executable is then presented as `Exec` once, through the same `is_executable` as before, and its
outcome is recorded. A denial of the `Exec` is the absent answer and the walk continues to the next
entry, as a denied candidate did before; stopping at the denial would make `command -v` an existence
oracle over a directory the policy forbids, because the answer would differ by whether that entry
holds the name.

Every candidate still passes through the interceptor, so the module's rule that every filesystem
effect is admitted here holds, and an embedder's deny-only floor bounds each candidate. What changes
is what a `Locate` means to an interceptor: the box's policy adapter answers it with a permit that
records nothing and makes no decision, and the box's floor refuses a candidate under a box's own
authority and records no decision either way, because a `Locate` maps to no action and the box
records governed effects. The box's two interceptors refuse a verb they do not name, so a
`Locate` neither knew would be `not found` rather than a program resolved past its floor.
`exec.rs::find_in_path` delegates to the new method, and
`builtins/hash.rs` loses its own copy of the walk, so command dispatch, `command -v`, and `hash`
resolve through one function. `FsOperation` is `#[non_exhaustive]`, so the variant is additive for a
reader and a new arm for an exhaustive match. `Mediated::find_in_path` is `pub(crate)`.

**Behaviour change for history.** An entry that holds nothing leaves no `fs:read` event, so a
`when temporal` rule that counts `fs:read` sees fewer events than before. The selected candidate
still records one `fs:read` event, and a program spelled with a separator is unchanged.

**Residual, stated.** The `Exec` decision fires only for a candidate the kernel calls executable, so
for a directory the policy forbids but the operator's lists reach, the resolution's latency and its
`fs:read` count differ by whether that directory holds an executable file of the name. The walk's
answer does not differ, and the floor-refused set does not differ either way, because a `Locate` the
floor refuses raises no `Exec`. Deciding once instead of once per candidate is what leaves this one
bit, existence of an executable regular file under a granted list, in the decision's side effects.

`tests/kernel_effect_interception.rs::path_resolution_raises_one_exec_decision_for_the_selected_candidate`,
`command_v_and_hash_resolve_with_the_same_single_decision`, and
`a_path_entry_outside_the_kernels_reach_is_not_observed` each fail against the prior walk and pass
after the change. `a_denied_selected_candidate_does_not_run` and
`a_denied_candidate_is_refused_and_the_walk_continues` are regression guards that pass before and
after; the second counts the one refusal the denied candidate receives.
`a_refused_locate_raises_no_exec_and_the_walk_continues` pins that a candidate whose `Locate` is
refused raises no `Exec` and the walk goes on. The policy crate pins the
history half in
`tests/temporal_shell_e2e.rs::a_path_walk_leaves_no_history_for_the_entries_that_hold_nothing`,
which fails against the prior walk, and guards the refusal in
`tests/policy_shell_fs_e2e.rs::forbidding_the_selected_candidates_exec_probe_keeps_it_from_running`.
The box pins the floor in
`run/broker/shell.rs::a_locate_inside_trusted_box_state_is_beneath_the_floor_and_records_no_decision`.

**Not upstream-worthy in this shape.** Upstream has no admission on the walk, so the defect does not
exist there. If the effect seam is offered upstream, `Locate` goes with it.

Verified after this change: `cargo test -p strands-shell --all-features` green, and the crate's
clippy warning count **unchanged at 18** with `--all-targets --all-features`.

## 2026-09-23 — the macOS descriptor-bound `chmod` refused a mode-0 file the process owns

The descriptor-bound host `chmod` (added 2026-09-12) opens the leaf under the verified parent
descriptor, checks its identity, and changes that exact object, so a leaf swapped for a symbolic
link cannot redirect the change. On Linux it opens with `O_PATH`, which needs no access right. On
macOS there is no `O_PATH`, and the branch used `O_EVTONLY | O_NOFOLLOW` as the stand-in. `O_EVTONLY`
is not access-free: it still needs read authorization, so `openat` returns `EACCES` on a mode-0 file
the process owns, before `fchmod` runs. A workload could not restore permissions on a file it had
set to mode 0.

The macOS branch now verifies the leaf identity with `fstatat` and changes it with `fchmodat`, both
against the parent descriptor `opened_parent` already pinned by (device, inode), and both
`AT_SYMLINK_NOFOLLOW` so a swapped leaf symbolic link is not followed. This keeps the identity
binding and leaves the setuid/setgid/sticky refusal above it untouched. It accepts the same
stat-to-syscall gap already recorded for the synchronous host effects, which is the closest macOS
analog to Linux's access-free `O_PATH` open. `chmod_restores_a_host_file_with_no_permissions` pins
the mode-0 case, and `symbolic_chmod_on_a_setgid_host_file_succeeds` keeps the setgid path green.

This is a portability fix to code this fork already carries, not an upstream defect. On Linux the
`O_PATH` path is unchanged.

Verified after this change: `cargo test -p strands-shell --all-features` green, and the crate's
clippy warning count **unchanged at 18** with `--all-targets --all-features`.

## 2026-09-24 — `rename` reported no fact about its destination, so an overwrite was judged as a move only

`Mediated::rename` presented `FsPairOperation::Rename` with the two resolved paths and nothing else.
A rename onto an existing file removes that file's content, and an interceptor could not tell that
rename from one onto an absent name, so a refusal to delete the destination never applied to
`mv payload protected`, while `cp payload protected` was already presented as a write to it.

`FsPairOperation::Rename` now carries `destination_exists` and `destination_is_dir`.
`Mediated::rename` reads both with one `Kernel::lstat` on the resolved destination path, after both
resolutions and before admission, so the facts name the object the rename acts on and the probe
raises no admission of its own: the rename attempt already names the destination. The probe does
not follow a final symlink, because the resolved destination of a dangling symlink is the symlink's
own name and `rename` replaces that name; a followed `stat` reported it absent. The token's identity
binding (2026-09-12) already refuses the rename when the destination changes between resolution and
the effect, with `filesystem identity changed during effect admission`, so a destination planted
inside the admission window is not replaced.
`in_mount_admission_window.rs::a_destination_planted_inside_the_admission_window_is_not_replaced`
pins that on a host bind, and `kernel_effect_interception.rs::a_rename_reports_whether_its_destination_exists`
pins the facts for an existing file, an absent name, a symlinked destination, a dangling symlink,
and a directory. On the in-memory VFS the kernel's resolution generation, which every
namespace-changing effect advances, does the same work as the host identity. On a host bind
`resolve_host` does not host-back a dangling symlink, so the fact reads absent there and the kernel
refuses the rename itself with `cannot rename between host and virtual filesystem`;
`in_mount_admission_window.rs::a_rename_onto_a_dangling_host_symlink_is_refused_by_the_kernel`
states that limitation.

This belongs upstream. The effect seam's contract is to present what an effect does, and a rename
that removes content is a different effect from one that does not; the seam's consumer cannot
recover the fact after the rename ran. The variant changes shape, so every constructor and match
on `FsPairOperation::Rename` in this crate's tests moved with it.

Verified after this change: `cargo test -p strands-shell --all-features` green, and the crate's
clippy warning count **unchanged at 18** with `--all-targets --all-features`.

## 2026-09-28 — a dangling symlink was judged on its own name, so a denial showed whether its target exists

This corrects the local effect seam (2026-08-05), not upstream code. `VfsKernel::resolved_target`
walked up to the nearest ancestor that canonicalizes and appended the missing tail. When the first
missing component was a dangling symlink, the result was the link's own name, but the kernel follows
the link. So the approved identity and the acted identity were different. A workload used this as an
existence oracle (found by a penetration test): `cd` through a link to an existing out-of-scope path
was denied, and `cd` through a link to a missing path was admitted and failed with ENOENT.

`resolve_existing_prefix` now replaces a dangling symlink with the path it names and resolves again,
up to `MAX_SYMLINK_HOPS`. A path that `Vfs::resolve` refuses with `vfs::SYMLINK_LOOP` keeps its
spelling, so a chain longer than the kernel follows fails with a loop error whether or not its target
exists. Before that check, a chain of 41 dangling links still gave the existence bit. A chain of
exactly 40 links needs 41 passes, 40 replacements and the final canonicalization, so the loop runs
`0..=MAX_SYMLINK_HOPS`.

That change alone made `mkdir` and `mv` follow a dangling link at the final component and create the
target. So `Mediated::create_dir` and the destination of `Mediated::rename` are now `Follow::No`, as in
`mkdir(2)` and `rename(2)`. Their parents still resolve, so `mv x /alias/key.pem` with
`/alias -> /secrets` is still judged on `/secrets/key.pem`. A symlink at the final component is the
name that the operation acts on, whether it is dangling or live, so neither the verdict nor the error
depends on its target. `mkdir` onto a symlink fails with "already exists". `mv` onto a symlink
replaces the link and raises `fs:delete` on it, as the 2026-09-24 entry states for a dangling link.
One behaviour moved: before, `mv` onto a *live* in-memory symlink wrote the link's target.

On a host bind, `rename_effect` refuses a destination that is a host symlink, live or dangling, with
`cannot rename onto a host symlink`. `lstat_effect` resolves a host path through `resolve_host`, which
follows symlinks, so the destination fact describes the target and `fs:delete` cannot be raised on the
link. Refusal is the smaller change, and inside a box the floor refuses the path first. Making the host
fact no-follow would let the rename replace the link instead. Before, a live host link was written
through and a dangling one was refused with `cannot rename between host and virtual filesystem`,
which the 2026-09-24 entry above states.

`resolve_host_for(.., Follow::No)` treats a final component that is itself a bind (`HostFile` or
`HostDir`) as the bind. Without that, the no-follow `mkdir` and rename saw an in-memory parent and
replaced a read-only bind in the namespace. `remove_file_effect` and `symlink_effect` also resolve
through `resolve_host_for(.., Follow::No)`, so each refuses a bind point with `bind mount point is
busy`. Otherwise `rm` on a writable file bind would unlink the operator's host file, where before it
removed only the in-memory entry. The host rename source still resolves with follow, as on
the pinned revision, and the identity check refuses a rename whose source is a host symlink.

- `kernel_effect_interception.rs::a_dangling_symlink_is_no_existence_oracle` pins the `cd` case.
- `::mkdir_and_mv_act_on_a_final_symlink_itself` pins `mkdir` and `mv` onto live and dangling links.
- `::resolve::a_dangling_symlink_resolves_to_the_path_it_names` pins the resolver.
- `::resolve::a_symlink_loop_terminates` pins the hop bound, with a ten-second timeout.
- `::a_rename_reports_whether_its_destination_exists` pins a rename onto a live link.
- `in_mount_admission_window.rs::a_rename_onto_a_dangling_host_symlink_is_refused_by_the_kernel` and
  `::a_rename_onto_a_live_host_symlink_is_refused_by_the_kernel` pin the host rename.
- `kernel_effect_interception.rs::a_long_symlink_chain_is_no_existence_oracle` pins the loop check
  at 40 and 42 links.
- `in_mount_admission_window.rs::a_rename_onto_a_read_only_bind_point_is_refused` and
  `::a_writable_bind_point_is_not_removed_or_replaced` pin the bind point.
- `in_mount_admission_window.rs::mkdir_onto_a_host_symlink_does_not_show_whether_its_target_exists`
  pins the host `mkdir`: before, a live link gave "identity changed" and a dangling one "not a
  directory".

Not fixed here: on a host bind the box floor's refusal reason shows whether a host path exists
(`approve_host`, recorded in `crates/policy/AGENTS.md`). That is the same class of oracle, in
`crates/policy`, and it needs its own change. A Shell with no box floor still follows an in-mount
host symlink, which the box floor refuses.

## 2026-09-29 — a path of many missing components held the VFS lock for time quadratic in its length

A penetration test found that `cat /workspace/a/a/.../a` with 16,000 components used 57 s of CPU in
one synchronous call. The call holds `VfsKernel::vfs`, so every other operation in the box waits, and
`Shell::timeout()` cannot stop it. Two walks caused this, and each walk alone is quadratic.

- `VfsKernel::resolve_existing_prefix` is part of the local effect seam (2026-08-05). It walked up
  one component at a time and called `Vfs::canonicalize_path` on each parent. That call normalizes the
  whole parent again. Now `Vfs::canonicalize_prefix` walks the path forward one time. It returns the
  canonical form of the longest prefix that canonicalizes, and the number of components in that
  prefix. `canonicalize_depth` uses the same walk, so `canonicalize_path` does not change.
- `VfsKernel::resolve_host` is from the pinned revision. It walked up and called `Vfs::resolve` on
  each prefix to find a `HostDir` ancestor. Upstream would call this a bug, because the operation hangs.
  A path does not resolve past a `HostDir`, and a prefix resolves when a longer prefix resolves. Thus
  only the longest prefix that resolves can be the ancestor. A binary search now finds that prefix
  with `O(log N)` resolutions.

With only one of the two fixes, 16,000 components took 19 s or 80 s. With both, it takes less than
0.1 s. `path_resolution_cost.rs::a_missing_path_of_many_components_resolves_in_linear_time` pins
this, under a bind and in memory. It compares 16,000 components with 2,000 in the same run, and
refuses more than 24 times the short time plus 1 s. A linear walk takes about 8 times as long, and a
quadratic walk about 64 times. The ratio does not depend on the speed of the machine.

The `vfs_kernel::resolve_host_tests` unit tests pin the result of `resolve_host`: a bind reached
directly or through a symlink chain, a missing tail below a bind, a `..` component, a host symlink
that dangles or leaves the bind, and a path with no bind ancestor. The same tests pass on the walk of
the base revision, so they pin the old answers. Each of these defects fails them: a search that
checks only the full path, an off-by-one tail, and a search that does not normalize its input.

The crate's clippy warning count is **unchanged at 17** with `--all-targets --all-features`.

Not fixed here: a path is not limited in length. `Vfs::canonicalize_path` also builds its base
string again at each symlink component, so a deep in-memory tree with a symlink at each level
remains quadratic. To build that tree, a workload must first create each directory with one
operation.

`resolve_host` normalizes its input before the search, because a `..` component makes resolution
not monotone. `mkdir -p` with N levels still costs about N² log N in total, because each level
resolves its own path. The VFS lock is released between levels, so one call does not hold it.

## 2026-09-30 — Claude Code's Bash preamble ran with a diagnostic on every command

Claude Code wraps each Bash tool call in a bash preamble: it sources a snapshot file it wrote at
session start, then runs `shopt -u extglob 2>/dev/null || true && { \builtin unalias -- 'unsetenv';
\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval '<command>' < /dev/null && pwd -P
>| <cwd file>`. The snapshot holds `shopt -s expand_aliases` and shell functions for `rg`, `find`,
`grep` and `pkill` written in the `function name { … }` form with `${1+"$@"}`, `[[ … ]]`, and, in
`pkill`, bash arrays. Bash runs all of it silently. Through this crate every command printed
"unterminated double quote" and "builtin: command not found", and the snapshot script itself died at
`declare -F | … | while read func; do`. Eight upstream defects, each a wrong result against bash:

- **`builtin` was not a builtin**, so `\builtin unalias` was "command not found". `builtins/builtin.rs`
  runs the named builtin past a function of that name; `execute_pipeline_checked` drops the prefix
  before a special builtin. `unalias` and `unset` did not accept `--`.
- **`shopt` was not a builtin.** `builtins/shopt.rs` accepts bash's option names with `-s`, `-u`,
  `-q`, `-p`, refuses an unknown name as bash does, and records the state on `Process::shopts`
  without giving it an effect.
- **A `"` inside `${name op word}` was collected as literal text**, so `${1+"$@"}` expanded to the
  four characters `$@`, and `${_cc_probe[@]+"${_cc_probe[@]}"}` lost the closing brace to the
  nested expansion and left the tokenizer inside an unterminated string. `collect_brace_word` parses
  the region with `collect_double_quoted`, the same collector the tokenizer uses; `collect_var_name`
  keeps a `[subscript]`; `expand_part_split` expands the selected word of `-` and `+` part by part
  so `"$@"` keeps its fields. A subscript on a scalar reads as bash reads it: `${x[0]}`, `${x[@]}`
  and `${x[*]}` are `$x`, any other index is unset, `${#x[@]}` is `1` or `0`.
- **The `function name { … }` and `function name () { … }` forms were not parsed.** The keyword
  ran as a command and the body ran at definition time.
- **A pipeline could not feed a compound command.** `cmd | while read x; do …; done` was
  "unexpected 'do'". `Item::PipelineIntoCompound` runs the head captured and hands its output to
  the compound on stdin, in a fork as bash does.
- **Redirects on `source`, `.` and `eval` were dropped**, because the special-builtin path never read
  `pipeline[0].redirects`. They are now applied the way a redirect on a group is. The same dispatch
  was missing from every capture: `$(eval …)`, `$(source f)` and `$(command …)` expanded to nothing,
  because `run_capturing_status` ran a pipeline through `run_pipeline` alone. `capture_pipeline_checked`
  routes a captured pipeline through `execute_pipeline_checked` with fd 1 held back, so the special
  builtins run and a group's stdout inside `$( )` is captured rather than written to the process.
- **A redirect of fd 2 did not reach the shell's own diagnostics.** A builtin's `err_msg` went to
  the process channel, so `unalias x 2>/dev/null` still printed, and a group's `2>/dev/null`,
  `2>file` and `2>&1` lost stderr entirely, `{ echo hi; } 2>&1` printed nothing, and with an
  embedder's writer on fd 2 every diagnostic inside `{ … } >/dev/null 2>&1` reached the embedder.
  The single-builtin arm drains `err_msg` into the redirect's target; a redirected group drains
  fd 2 and `err_msg` into a buffer (`DivertedStderr`) while it runs and delivers both streams by
  the redirects in order (`GroupSink`), so `2>&1 >file` keeps stderr on the original stdout.
- **`head -N` and `tail -N`**, the obsolete count coreutils still accepts, were "invalid option".

Two additions beside the fixes, both bash syntax with no counterpart here. `name+=value` appends,
where before it set a variable named `name+`. An array literal `name=(…)` or `name+=(…)` parses as
`WordPart::ArrayLiteral`, so a function body that holds one defines as in bash; running one refuses
with "arrays are not supported" and the expansion-error exit, because a shell without arrays that
guesses at them would return wrong results silently.

`tests/claude_code_preamble.rs` holds the captured snapshot-creation script from Claude Code 2.1.285
and its per-command wrapper as fixtures, asserts an empty stderr through `Shell::run` and through an
installed stderr channel, and pins each construct above. `tests/fixtures/claude-code-snapshot-script.sh`
is the capture with only the home path generalised.

Not fixed, and still a diagnostic in the snapshot script's own stderr, which Claude Code discards
unless creation fails: `[[ … ]]`, `declare`, `set -o`, and `printf %q`. `[[` also runs inside the
`rg`, `find` and `grep` shadow functions when a command calls them. This change left the
multi-line executor's habit of accumulating every line after a real parse error until end of input.
The entry "a parse error inside `source` consumed the rest of the file" fixes it. Two limits of the group redirect stay: the two streams are captured apart, so
`{ echo a; echo b >&2; } >f 2>&1` writes `a` then `b` whatever order they were produced in; and a
background job started inside a redirected group is awaited before the group returns, as it was
before this change.

A pipeline into a compound command is not concurrent. The head runs to its end before the compound
starts, so `tail -f log | while read l; do …; done` does not enter the loop, where bash runs both
sides at the same time.

The first version of `DivertedStderr` read its channel only after the group returned. The channel
holds 64 chunks, so a group that wrote more than that to stderr under a redirect blocked on the next
write and did not return, and `err_msg` lost each message after the 64th.
`(cd crate && cargo test) 2>&1 | tail -50` is that shape. The channel is now drained into a buffer
while the group runs, as `run_pipeline` drains a builtin's streams, and the output limit applies to
the buffer. `claude_code_preamble.rs::a_group_writing_many_stderr_lines_to_dev_null_is_silent_and_finishes`,
`::a_group_writing_many_stderr_lines_to_stdout_keeps_every_line_in_order`, and
`::a_group_writing_many_stderr_lines_piped_to_tail_yields_the_last_lines` each write three hundred
lines; with the unread receiver restored, all three run to their deadline and fail.

Three defects of the pinned revision were found beside that change and stay as they are. A
redirected group returns the process's last exit status, not the group's own, so
`{ echo done; false; } 2>/dev/null` exits 0 and `{ while …; done; echo done; } 2>/dev/null` exits 1.
The parser drops a `!` before a compound command that no pipe follows, so `! (false)` exits 1. A
subshell's stderr is lost under any capture, so `{ (echo x >&2); } 2>&1` and `$( (echo x >&2) )`
print nothing. The snapshot's `if ! (unalias rg 2>/dev/null; command -v rg) >/dev/null 2>&1` defines
`rg` only because the first two cancel out.

`builtin X` was admitted as the program `builtin` when `X` was not a special builtin, so a rule on
`cd` did not hold for `builtin cd`, and the record named `builtin`. `execute_pipeline_checked` now
drops the prefix before any name `builtins::lookup` knows, so `X` is admitted and recorded; a builtin
already resolves ahead of a function in `run_pipeline`, which is all the prefix means in bash, and an
unknown name keeps the prefix and reaches `builtin_builtin`'s refusal.
`claude_code_preamble.rs::builtin_is_admitted_as_the_program_it_names` pins it; with the
special-only condition restored, `builtin cd /tmp` passes a rule that forbids `cd`.

All of it belongs upstream. Offer it upstream.

## 2026-10-01 — `mkdir -p` created an ancestor it could not see

GitHub issue #81 (box). With `fs:read` and `fs:write` permitted below `/home/lash/project/`,
plain `mkdir /home/lash/project/e` and relative `mkdir -p a/b` succeeded, but
`mkdir -p /home/lash/project/c/d` failed with `policy denied this operation on '/home'
[default-deny]`. The target was never named.

The builtin walked the path from the root and called `Mediated::stat` on each prefix. A denied
probe returns the not-found stat by design, which is also what a missing directory returns. The
builtin read that answer as missing and called `create_dir` on `/home`, which raised `fs:write` on
an ungranted ancestor. Upstream would call this a bug: the builtin acts on an answer that does not
say what it needs to know, and the result is wrong. This is upstream's own code, from the pinned
revision.

`Mediated::stat_if_admitted` is a crate-private probe that returns `None` when the probe is refused,
and `Some(stat)` with the kernel's answer when it is admitted. `Mediated::stat` is now that probe
with `None` folded into the not-found stat, so the workload observes no change. `mkdir -p` walks
the ancestors with the new probe:

- an ancestor that exists, or whose probe is refused, is not created;
- the first ancestor the kernel reports missing starts creation, and each deeper component is
  created without a further probe, until a `.` or `..` component, which names a directory that
  exists and starts the probes again;
- the target itself is probed with `Mediated::stat` as before, and created when it is not seen,
  so a refused target is named in the denial.

Two options were rejected. Creating the target first and walking up on a not-found cannot work on a
host bind: the kernel reports a write under a missing parent as the fail-closed identity refusal,
which `in_mount_admission_window.rs::a_host_effect_with_an_unbindable_identity_fails_closed` pins.
Treating a refused probe as missing and tolerating a refused `create_dir` on an ancestor would
raise and record an `fs:write` denial on every ancestor, which is the behaviour this change removes.

- `policy_shell_fs_e2e.rs::mkdir_p_with_an_absolute_path_creates_every_missing_component_below_a_grant`
  pins the issue's case.
- `::mkdir_p_with_a_relative_path_creates_every_missing_component` pins the relative path.
- `::mkdir_p_below_an_ungranted_parent_is_refused_and_names_the_target` pins the denial text:
  `policy denied this operation on '/home/lash/other/x' [default-deny]`, and no `'/home'`.
- `::plain_mkdir_is_unchanged_by_the_parents_walk` pins plain `mkdir` on both sides of the grant.
- `kernel_effect_interception.rs::mkdir_p_creates_no_ancestor_whose_probe_is_denied` pins the
  effect sequence: `create_dir` reaches `/home/lash/project/c` and `/home/lash/project/c/d`, and no
  `create_dir` reaches `/home`, `/home/lash`, or `/home/lash/project`. The `Recorder` in that file
  now keeps every attempted effect beside the admitted ones, so a test can assert on a refused one.
- `::mkdir_p_accepts_a_dot_component_after_a_created_one` pins `new/../sib` and `b/.` after a
  created component. A first version of this walk created `new/..` and failed with "already
  exists", which the pinned revision did not.

With the walk of the pinned revision restored, the first, third, and fifth of these fail, and the
first two failures show the `'/home'` text from the issue.

The crate's clippy warning count is **unchanged at 17** with `--all-targets --all-features`.

One behaviour moved: a grant of `fs:write` with no `fs:read` on the same directory can no longer
create more than one missing level, because every probe is refused and the builtin does not create
what it cannot see. The `create_dir` of the target then reports the first missing component on the
in-memory kernel, and the identity refusal above on a host bind. Before, this worked when every
ancestor was also writable, and failed on `/home` otherwise. The examples permit `fs:read` and `fs:write` on the same pattern.

Not fixed here: a refused probe on an ancestor is still recorded as a denied `fs:read`, one for
each ancestor above the grant, as before.

## 2026-10-01 — a glob of three or more levels listed a directory it did not authorize

GitHub issue #158 (box), a pen-test finding. With a `forbid` on listing `/tmp/private`,
`ls /tmp/*/*` dropped `/tmp/private/file`, but `ls /tmp/*/*/*` returned `/tmp/private/sub/file`.
`Mediated::glob` asked for `Enumerate` on the literal prefix and on the parent of each match. The
walk also read each directory between the two, and no decision covered it, so the name `sub` came
out of `/tmp/private`. Each more wildcard level added one more directory with no decision. The same
code gave the prefix and the parent of a relative pattern with no `/` before its first wildcard as
`/`, so `echo *` in a directory that policy refuses to list was judged on `/`. The defect is in
`src/mediate.rs`, which is a local addition (see "the effect seam covers the filesystem"), and not
in upstream's code. The fix stays in that file, so the kernel walk still authorizes nothing and the
divergence from upstream does not grow.

`Mediated::glob` now authorizes each directory from the prefix down to the parent of each match, in
that order. It keeps one list of decisions for each expansion, so it asks about each directory one
time, and the prefix decision covers the prefix. A refused directory drops every match below it,
and the walk raises no decision below it. A relative pattern with no `/` before its first wildcard
starts from `.`, and a match with no `/` has the parent `.`. A pattern with no wildcard starts from its parent,
so it raises no decision on an ancestor. The kernel walk is unchanged, and no
match leaves `glob` before its directories are authorized.

- `kernel_effect_interception.rs::three_wildcard_levels_enumerate_no_refused_intermediate_directory`
  pins the issue's case and the decision sequence: one `enumerate` for each directory, and none
  below the refused one. No effect of any kind reaches a path below the refused directory.
- `::two_wildcard_levels_drop_a_match_in_a_refused_directory` pins the two-level case.
- `::a_relative_glob_enumerates_the_working_directory` pins `echo *` in a refused directory and a
  relative three-level pattern.
- `::glob_enumeration_decisions_are_one_for_each_directory_read` pins 10 decisions for a tree of
  3 × 2 × 3 files under one prefix.
- `test-integ` case `SH-SEC-GLOB` pins the issue's case through a real box and an authored
  `forbid`.

With the pinned check restored, the first, third, and fourth of these fail, and `SH-SEC-GLOB`
prints `G3=/tmp/t/private/sub/file`.

The crate's clippy warning count is **unchanged at 17** with `--all-targets --all-features`.

One behaviour moved: a single-level pattern such as `/tmp/*` raised `Enumerate` on `/tmp` two times,
and now raises it one time.

Not fixed here: the in-memory kernel walk does not read a host bind, so a pattern below a host bind
expands to nothing.

## 2026-10-02 — a write over `max_file_size` was cut short with exit 0, and a bound host directory had the same cap

GitHub issue #73 (box). With the default cap of 10 MiB, `cp`, `cat >`, `printf >`, and
`>>` exited 0 with empty stderr when the bytes crossed the cap, and the file held a prefix. The
prefix was not the cap: the drain task dropped the 8 KiB chunk that crossed the cap and every
chunk after it, so a cap of 16 bytes left a 0-byte file. The `file size limit exceeded` text
existed, but only on a later write to the same descriptor, after the drain task had run; a command
that wrote and closed never saw it. A redirected group opened its file after the commands ran and
discarded the write error, and a forked process inherited an embedder's output writer without its
error flag, so the second writer saw `pipe closed`. The same cap applied to a write into a
`bind_direct` host directory, where the file is on the operator's disk and the cap protects
nothing. Upstream would call the silence a bug: a write that loses bytes must fail. The cap on a
host bind is a product decision recorded in the box's design: a bound directory follows the host
filesystem's own limits, as bash does.

`os::WriteLimit` is the byte budget of one open file. It is shared by every descriptor that writes
the file, including a `dup`, and `FdWriter::poll_write` counts each accepted chunk against it. A
write that does not fit is accepted up to the cap and the next write is refused with
`file size limit exceeded (<cap> bytes)`, which is the shape a kernel gives a process under
`RLIMIT_FSIZE`: the partial file up to the limit is kept, the command exits non-zero. An append
to a file already at the cap is refused at open with the same text, before any write. The drain
tasks no longer cap. A backing-store failure returns from the drain task, and `settle_writes`
reports it to the command (the entry below). The in-memory open sets the budget from
`max_file_size`, and a `bind_direct` open sets no budget. `Vfs::write_file` and
`Vfs::append_file` keep their cap and now name it in their message.
`Process::inherit_channel_writer` gives a forked process the writer and its budget, and the
single-command and pipeline arms use it in place of a clone of the sender alone; no test pins the
budget's inheritance, because no shell construct installs a budgeted writer on the shell's own
process today (`exec >file` is not implemented at the pinned revision), and an embedder's
`set_channel_writer` installs none. A redirected group reports a refused open or a failed write of
its captured output as `strands-shell: <path>: <error>` and exits 1; before, both were discarded
and the group exited 0. `Process::out_msg`, `out_raw`, `err_msg`, and `err_raw` send to a channel
writer through the same budget, so no route onto a descriptor can pass the cap; no test pins that,
because no shell construct reaches a budgeted writer by those routes today.

- `write_cap.rs::a_write_under_the_cap_lands_in_full`, `::a_write_exactly_at_the_cap_lands_in_full`,
  `::a_write_one_byte_over_the_cap_is_refused_and_keeps_the_prefix`, and
  `::a_write_well_over_the_cap_is_refused_and_keeps_the_prefix` pin the boundary at a 64-byte cap
  for `cp`, `cat >`, `printf >`, `>>`, a `{ ...; } >` group, and an `a | b >` pipeline: exit 0 and
  every byte when the write fits, and otherwise a non-zero exit, the refusal text, and exactly the
  cap on disk.
- `::an_append_to_a_file_at_the_cap_is_refused_at_open` pins the open-time refusal with
  `true >> file`, which writes nothing, and the refusal of `printf x >> file`.
- `::a_group_appending_to_a_file_at_the_cap_is_refused` pins the group's report of a refused open.
- `::a_bound_host_directory_has_no_cap` pins `cp`, `cat >`, a pipeline, and `>>` of 12 MiB into a
  `bind_direct` directory with a 64-byte cap in the builder: exit 0, empty stderr, and a
  byte-identical host file read after the drain tasks complete.
- `shell_integration.rs::builder_max_file_size`, `::config_file_vfs_caps_applied`,
  `::max_file_size_single_write_error`, and `::max_file_size_append_loop_blocked` now assert the
  non-zero exit and the refusal text beside the size bound they already asserted.

With the budget check in `poll_write` removed and the drain task's silent `break` restored, the
over-cap tests fail with exit 0 and an empty stderr. With the cap applied to the `bind_direct` open
again, `a_bound_host_directory_has_no_cap` fails on every command.

The crate's clippy warning count is **unchanged at 17** with `--all-targets --all-features`.

Fixed in the entry below (#262): a command's status waits for its drain task, and the drain task
of a `bind_direct` write streams each chunk to the host file as it arrives, so the memory the
trusted process holds for one writer stays bounded after the cap is removed here. The tests here
read the host file after the drain tasks complete, and the in-memory file after yielding to them.
A redirected group whose captured output exceeds `max_output` still exits 0 with `pipe closed`
and a cut-short file, because the group's capture is bounded by the output cap and not by this
one.

## 2026-10-02 — a command returned its status before its file write reached the host

GitHub issue #262 (box). A write through the shell (`cp`, `cat >`, `printf >`, `>>`,
`tee`, a `{ } >` group, an `a | b >` pipeline) sends its bytes into a channel, and a `spawn_local`
drain task in `src/vfs_kernel.rs` moves them to the in-memory VFS or to the host file when every
writer is closed. The command's status was returned as soon as the writer closed, before the drain
ran. Measured on main 8095a32a, x86_64 Linux, with a 10485759-byte `cat src > dst` on a
`bind_direct` directory: exit 0 with the host file at 0 bytes; `wc -c < dst` in the next command
printed 0; a new Shell on the same bind read 0 bytes; and with the Tokio `LocalSet` dropped before
the drain ran, the host file stayed at 0 bytes. The same window exists on the in-memory VFS.
`Shell::write_file` already waited, by polling `stat` until the length landed; a command did not.
Bash is the reference: when a command exits, every byte it wrote is visible to the next command.
Durability is not required, and is not added here.

`VfsKernel` now keeps one `PendingWrite` for each file drain it spawns: a `WeakSender` to the
descriptor's channel and the drain's `JoinHandle`. `Kernel::settle_writes` is a new trait method,
and the VFS kernel's body awaits every drain whose channel has no live sender left and leaves a
drain whose writer is still open alone. The method has no default body: the box wraps the kernel in
a forwarding `CallKernel`, and the first version of this change gave the method an empty default, so
that wrapper forwarded nothing and the box returned a status with the host file still at 0 bytes. A
kernel that spawns no drain states so by returning, and a wrapper forwards.
`Mediated::settle_writes` forwards it and raises no admission, because the bytes were admitted when
their descriptor was issued. `exec::execute_item` returns an item's status only after
`settle_writes`, so the guarantee holds between the items of one submission (`a > f; cat f`) as well
as between submissions, and it is the one settle point: the `{ } >` group sink's `yield_now` is
removed and the sink adds no call of its own. Each drain returns its `io::Result`, `settle_writes`
reports each drain that failed as a `WriteFailure` naming the path, and `execute_item` then prints
`strands-shell: <program>: <path>: <error>` and returns status 1, so a host write that fails after
the open (a full disk, an I/O error) or a drain task that panics (`write task failed`) no longer
leaves a command at exit 0 with an incomplete file. `Shell::write_file` calls `settle_writes` in
place of its `STALL_LIMIT` polling loop, returns the first failure, and stats once. The two host
drains stream: each writes every chunk to the opened host file as it arrives, with the writer's
channel held at `HOST_WRITER_DEPTH` chunks, so the memory a `bind_direct` write holds in the trusted
process is bounded by the chunks in flight and not by the file, which the in-memory drain still has
to hold under its cap. A writer that is still open when an item ends belongs to a background job
(`&`), and bash does not wait for that one either; its bytes land when the job closes the
descriptor. The box's broker already awaits the connection's `LocalSet` at teardown, bounded by its
I/O timeout, so no pending drain is dropped at box exit.

- `write_visibility.rs::consecutive_commands_see_the_whole_write_on_the_host` and
  `::consecutive_commands_see_the_whole_write_in_memory` pin `cat src > dst; wc -c < dst` as two
  submissions for each of the seven writer spellings, at 10485759 bytes and at 1024 bytes.
- `::a_new_shell_on_the_same_bind_sees_the_whole_write` pins a second Shell on the same bind.
- `::the_host_file_is_complete_when_the_command_returns` measures the host length directly.
- `::the_write_survives_dropping_the_runtime` drops the `LocalSet` and the runtime after the
  command returns, then measures the host length.
- `::a_small_write_returns_within_the_sanity_bound` bounds twenty 1024-byte writes at an
  absolute 20 s, a bound a loaded runner cannot miss and a wait on a command deadline cannot meet.
- `::a_failed_host_write_fails_the_command` re-runs this binary as a child with `RLIMIT_FSIZE` at
  zero, so every host write fails with `EFBIG` on Linux and macOS, and pins status 1 and the
  message for `cat >` and `cp`, and that a later write elsewhere still settles. With the host
  drain's errors discarded again, the child sees exit 0.
- `::a_large_host_write_streams_through_the_drain` writes 64 MiB into a `bind_direct` directory
  from a 1 MiB piece named 64 times, in a child process, and pins that the peak resident size grows
  by less than 8 MiB and that every piece on the host matches its source; with the drain collecting
  the file before one write, the peak grows by 27 MiB and the test fails.
- `::a_host_write_that_fails_midway_fails_the_command_and_keeps_the_partial_file` sets
  `RLIMIT_FSIZE` to 1 MiB and writes 4 MiB, and pins status 1, the message, and a partial file.
- The box's `run::broker::host::tests::a_calls_write_is_on_the_host_when_its_status_returns` pins
  the same contract through the broker socket, over `CallKernel`.

With `execute_item` returning before `settle_writes`, the first five fail with the host file at
0 bytes; the sixth still passes.

The crate's clippy warning count is **unchanged at 17** with `--all-targets --all-features`.

Not fixed here: a `{ } > file` group above the shell's output cap (1 MiB) writes 0 bytes with
exit 0, because the group sink captures the body as one string bounded by `max_output` before it
opens the file. The two tests above hold that spelling, and `printf '%s' "$(cat src)"`, at one
byte under the cap. The in-memory cap and its refusal are the entry above (#73); a `bind_direct`
write has no cap, so the host drains count nothing against one.

## 2026-10-01 — a parse error inside `source` consumed the rest of the file

At the pinned revision, the parser returns `Result<_, String>`. `execute_sourced` treats each parse
error as a statement that needs one more line, so it adds the next line and parses again. Thus a
statement that no line can make valid consumes every line to end of file. The source then shows the
last error, at no line. That error can come from text after the defect, so it can name the wrong
construct. Each new line causes a new parse of all the text so far, so the time grows as the square
of the line count. Measured on a 135 KB zsh snapshot: 14.02 s, and the error was
`Opened parentheses without closing`, at no line. The defect was in the function that starts at
line 89. No definition after it loaded. Upstream would call this a bug, because the result is wrong
and the error is lost. The loop is the same on upstream `main` at `8f292766`.

The parser now returns `parser::ParseError`. `ParseError::kind` gives a `ParseErrorKind`, and
`Display` shows the message, so a caller that prints the error shows the same text as before. The
fields are private, and `ParseErrorKind` is `#[non_exhaustive]`, so a later kind does not break a
caller. `ParseError` implements `Display` and `std::error::Error` by hand. It does not derive
`thiserror::Error`, which `docs/conventions.md` asks of an owned crate, because the pinned revision
has no `thiserror` dependency.

This changes the public API of upstream: `parser::parse`, `parse_with_reader`,
`parse_with_aliases`, and `collect_dollar_pub` return `ParseError` and not `String`, and
`exec::execute_sourced` takes one more argument. A caller that uses the error as a `String` does not
compile. The alternative was to keep the `String` functions and add typed functions beside them.
That keeps two parsers' worth of entry points for one parser, and no caller in this workspace needs
the `String` form, so the signatures change. If upstream does not take this change, the divergence
stays at these five signatures.

Each error site returns one of two kinds:

- `ParseErrorKind::Incomplete` when the input stops inside a construct. Examples: an unterminated
  quote, a missing `fi`, `done`, `esac`, `}` or `)`, and a `|` at end of input.
- `ParseErrorKind::Invalid` when a token is wrong. Examples: `unexpected ')'`, a reserved word in the
  wrong position, and the `(` of the zsh glob qualifier `*(N)`.

For each site in the parser tests, more lines cannot make an `Invalid` statement valid, because the
token that is wrong is already in the text. This is not true for every input. The parser looks ahead
to find `name()`, so `f(` alone is `Invalid`, but `f(` followed by `) { …; }` is a function. That input
is not valid bash.

`execute_sourced` adds a line only for an incomplete statement. For an invalid statement, it stops
the source and returns 1, the status of the pinned revision. The alternative was to skip the
statement and continue at the next line. That alternative was not used, because a statement that
does not parse can be the start of a compound command, and the lines after it can then run out of
their context. For example, the body of a function or an `if` runs at the top level. To stop is the
safe result. bash and zsh also stop a sourced file at a syntax error.

The status stays 1, because the shells do not agree and the issue does not need a change. Measured:
bash 5.3.20 returns 2 for `.`, for a script, and for `bash -c`. zsh 5.9 returns 126 for `.` and 1 for
a script and for `zsh -c`. bash 3.2.57 returns 1 for `.` and 2 for a script. One Shell serves both
the `bash` and the `zsh` alias, so either value differs from one of them.

The error shows the line where the statement starts, and not the line of the wrong token. bash and
zsh show the line of the wrong token. Thus a defect inside a function shows the first line of the
function. The alternative was to keep a line number on each token. That changes `Token` and every
site that builds one, and makes the divergence larger. The form is
`strands-shell: <file>: line <n>: <message>`. `execute_sourced` takes an `origin` argument for the
file name. `run_script` and `.` give the path. The multi-line `execute` gives `None`, and then the
form has no file name. A statement that is still incomplete at end of file shows its start line.

At the pinned revision, a sourced line that ends with `&&` or `||` parses as complete. So
`false &&` with `echo x` on the next line ran `echo x`, and bash and zsh do not. `execute_sourced`
now adds the next line to a statement that parses with `&&` or `||` last, when the file has a next
line and no heredoc took lines. The parser does not change for this, so a single line, `eval`, a
trap, and `$( … )` keep the meaning of the pinned revision: `echo a &&` given alone runs `echo a`, as
zsh does. bash refuses it. An alias whose value ends with `&&` joins the next line in the same way,
as bash and zsh do.

At the pinned revision, a script that `sh` runs loses its stderr. The pipeline stage forwards the
script's `captured_output` to the stage's stdout and drops `captured_stderr`. So `sh <file>` hid
each error of the script, `command not found` included, and also the new parse error.
`forward_captured_streams` now forwards both streams for the script stage. The stage writes all of
the script's stdout, then all of its stderr, so the two are not interleaved as they are in bash. The
same loss applies to a function that runs as a pipeline stage, as in `f | cat`, and that is not
changed here. Forwarding it made Claude Code's wrapper show `[[: command not found` for
`rg x | head`, because the snapshot's `rg` and `grep` functions use `[[`, which this Shell does not
run. The wrapper is silent for that command at the pinned revision.

- `parser::tests::input_that_ends_inside_a_construct_is_incomplete` and
  `::input_that_no_later_line_can_close_is_invalid` pin the kind of each error site.
- `shell_integration.rs::source_stops_at_an_invalid_statement_and_names_its_line` pins the issue's
  case. A definition before the defect loads, and a definition after it does not. The error is
  `line 2: Opened parentheses without closing`.
- `::source_runs_nothing_after_an_invalid_top_level_statement` pins the stop and the error for
  `sh <file>` and for `.`, and the file name that `run_script` gives.
- `::source_still_joins_lines_of_an_incomplete_statement` pins a multi-line function, `for`, `$(`,
  a trailing `|`, `&&` and `||`, a heredoc, a heredoc on a line that ends with `&&`, an alias that
  ends with `&&`, and `case`.
- `::source_reports_an_unclosed_statement_at_the_line_where_it_starts` pins the end-of-file case.
- `::source_counts_lines_past_a_heredoc_and_a_multi_line_function` pins the line number after lines
  that a heredoc and a function use.
- `::multi_line_input_stops_at_an_invalid_statement_and_names_its_line` pins the form with no file
  name.
- `::an_operator_at_end_of_input_keeps_its_meaning_outside_a_sourced_file` pins `echo a &&` alone,
  in `$( … )`, in `eval`, and on the last line of a file. It also passes on the pinned revision.
- `::a_script_run_by_sh_reports_its_errors_to_the_caller` pins the stderr of `sh <file>`.
- `crates/box/tests/box_programs.rs::a_program_the_box_never_saw_behaves_like_a_unix_program`
  pinned the loss of a script's stderr as a known gap, and asked for a positive assertion when the
  gap closed. It now asserts that the script's stderr reaches the caller.
- In `test-integ`, `SH-SOURCE-STOP`, `SH-SOURCE-JOIN`, and `SH-SOURCE-STATUS` pin the same behaviour
  in a real box. In the box, `sh` is the host `/bin/sh`, so `SH-SOURCE-STATUS` reaches the Shell's
  script runner through `lash`. With the shell of the pinned revision, `SH-SOURCE-STOP` and
  `SH-SOURCE-STATUS` fail. `SH-SOURCE-JOIN` passes there: in the box, the pinned revision already
  skips the line after `false &&` and `true ||`, although the same file through `Shell::run` outside
  the box runs it. The box builds its Shell with its own kernel and an effect interceptor, and the
  cause of the difference was not traced. So in the box `SH-SOURCE-JOIN` pins the joined lines and
  the result, and `source_still_joins_lines_of_an_incomplete_statement` is the test that fails without
  the `&&` and `||` join. The check in `SH-SOURCE-STOP` that a later line reaches no policy decision
  also passes at the pinned revision, because the old loop runs no later line either. It is there to
  fail if a later change skips a bad statement and continues.

The first two integration tests end their file with an unclosed quote. If the loop consumes to end
of file again, the error changes to `unterminated double quote`, and both tests fail. Mutations, each
restored after the run:

- `(` set to `Incomplete`: `input_that_no_later_line_can_close_is_invalid` and
  `source_stops_at_an_invalid_statement_and_names_its_line` fail.
- `expected '<word>'` at end of input set to `Invalid`:
  `input_that_ends_inside_a_construct_is_incomplete` and
  `source_still_joins_lines_of_an_incomplete_statement` fail.
- The trailing `|` check removed: the same two tests fail.
- The `&&` and `||` join removed from `execute_sourced`:
  `source_still_joins_lines_of_an_incomplete_statement` fails.
- The join's check that no heredoc took lines removed: the same test fails, because the heredoc
  body then runs as a command.
- The loop changed to treat `Invalid` as `Incomplete`:
  `source_stops_at_an_invalid_statement_and_names_its_line` and
  `source_runs_nothing_after_an_invalid_top_level_statement` fail.
- The stderr half of `forward_captured_streams` removed:
  `a_script_run_by_sh_reports_its_errors_to_the_caller` and
  `source_runs_nothing_after_an_invalid_top_level_statement` fail.

On the same snapshot, the source now stops in 21 ms and shows `line 89`. Claude Code's wrapper,
over its captured snapshot and over a real zsh snapshot, gives the same stdout, stderr, and status
as at the pinned revision for each command tried.

The crate's clippy warning count is **unchanged at 17** with `--all-targets --all-features`.

Not fixed here:

- A statement that is not complete yet still causes a new parse of all its text for each line, so
  its time grows as the square of its length. Measured: a file with `echo "open` on line 1 and
  20,000 more lines (289 KB) used 38.4 s of CPU. The cost is not only for an attack: a function of
  1,500 lines used 0.85 s, 5,000 lines 9.3 s, and 10,000 lines 37.8 s, in a release build. The
  `nvm()` function of nvm is 1,465 lines. The workload controls this input, and the shell runs in the
  box's trusted process, beside the policy engine and the egress gateway. Thus a workload can use
  the CPU of that process when it wants to. This change does not reduce that risk. Three fixes were
  examined. First, parse the statement together with the rest of the file once, and report at once
  if it is still incomplete. That makes only a quote that does not close linear, and a long function
  is still quadratic. Second, a limit on the lines one statement can collect. The limit must be
  above 1,500 lines to keep nvm, and at that size the cost is still more than one second. Third, a
  parser that continues where it stopped. Only the third removes the cost, and it is a larger change
  than this one, so this entry records the cost and does not fix it.
- A function that runs as a pipeline stage still loses its stderr, as stated above.
- `$( … )` still returns 1 with no message when its text does not parse.

## 2026-10-03 — additive: a test pins that a spawn with no interceptor is permitted

A new, test-only local addition to the effect seam, like the 2026-09-01 entry. `admit_resolved`
permits a host spawn when the `Mediated` handle holds no interceptor. The box always installs one,
so this branch is not reachable in a box, and no test stated it.

- **`src/mediate.rs`** gains `#[cfg(test)] mod spawn_admission`: one test that admits a spawn
  through `Mediated::new(VfsKernel, None)` and asserts that it is permitted, issues no permit, and
  names no spawn program. Proven to fire on a planted refusal in the `None` arm, and restored green.

No production code changed.

## 2026-10-03 — `pyo3` moves from 0.28 to 0.29 with Monty 1.0.0

Monty 1.0.0 reaches `pyo3 ^0.29` through `jiter 0.17`. `pyo3` declares `links = "python"`, so one
graph holds one major version, and the 0.28 requirement in `Cargo.toml` made the workspace fail to
resolve. The requirement is now 0.29. The change is in the manifest only. The `python` feature that
enables `pyo3` is off by default, and no workspace crate enables it, so no build of the box compiles
`src/python.rs` against either version. This is not an upstream bug. It is divergence that follows
the box's own interpreter version, and a future upstream merge must keep it until upstream reaches
0.29 or later.

## 2026-10-05 — `curl` refused the options the Strands harness `web_fetch` sends

An upstream gap in the `curl` builtin, filed as
[strands-agents/shell#130](https://github.com/strands-agents/shell/issues/130) and fixed by
[strands-agents/shell#131](https://github.com/strands-agents/shell/pull/131). `web_fetch` sends
`curl -sSL -g --fail --proto '=http,https' --proto-redir '=http,https' --max-time N -A <ua> -o <out>
-w '%{content_type}\n%{url_effective}' -- <url>`, and the builtin refused `-g`, `--proto`,
`--proto-redir`, `--max-time`, and `-A`, wrote `%{content_type}` as an empty string, and left
`%{url_effective}` unreplaced. So `web_fetch` failed in every box.

Fixed in `src/commands/curl.rs`, applied verbatim from the upstream PR:

- `-g`/`--globoff` is accepted and does nothing; the builtin never expands `{}` or `[]`.
- `-A`/`--user-agent` sets `User-Agent` on every hop. `-H 'User-Agent: …'` takes precedence, and
  `-A ''` sends none.
- `-m`/`--max-time` bounds the whole transfer, redirects included, and exits `28`. `0`, or a value
  too large to represent, means no limit. On `wasm32` it is accepted and not enforced, because a WASI HTTP call blocks.
- `--proto` and `--proto-redir` take curl's list syntax (`=`, `+`, `-`, `all`, left to right). A
  refused URL exits `1`; a redirect hop must pass both sets, and each flag replaces the one before it. **They only narrow.** The SSRF floor,
  the egress gateway, and the policy still decide every request, so neither is a second authority.
- `-w` substitutes `%{content_type}` from the response header and `%{url_effective}` as the last
  URL after redirects. It expands in one pass, so a server's `Content-Type` is never read as a
  variable or an escape.
- `-w` always goes to stdout, and `-o` takes only the body and, as in curl, the `-i` headers. This
  replaces the 2026-09-18 fix above. `-w` is also written on the `--fail` (`22`) and timeout (`28`)
  exits, with `%{http_code}` `000` when no response came.
- A `Location` with any `scheme://` prefix is absolute. Before, `ftp://…` was resolved as a path
  relative to the current URL, so `--proto-redir` could never see a non-HTTP redirect.

The rest of the upstream PR's tests need a loopback server, which the floor here forbids, so they
are ported rather than copied. The server-free cases (`--max-time` and `--proto` argument errors, and
`--proto` refusing the first URL) are in `tests/curl_integration.rs`. The server-backed cases go
through a scripted multi-response proxy in `tests/egress_proxy.rs`; `the_web_fetch_command_line_works`
runs `web_fetch`'s full command line, `-o` included, across a redirect.

The pinned revision's credential injection stays absent, as before.

## 2026-10-06 — `mv` accepts `-f` and `--force`

The upstream `mv` builtin refused `-f` and `--force`, although it already overwrites without a
prompt. The Strands harness `web_fetch` ends its command with `mv -f OUT.part OUT`, so this
refusal also affects Box.

This copy applies [strands-agents/shell#136](https://github.com/strands-agents/shell/pull/136)
at commit `5926965a7004cbe58dc95470746fc1333b846beb`. Both flags are accepted and do nothing.
The help text lists them. The upstream tests `mv_force_overwrites` and `mv_long_force_overwrites`
in `tests/shell_integration.rs` check that each flag permits replacement of an existing destination.

## 2026-10-06 — `head` accepts the byte limit used by `web_fetch`

`head` refused `-c`, so the Strands harness `web_fetch` could not limit a downloaded body.
At the user's request, this port applies
[strands-agents/shell#135](https://github.com/strands-agents/shell/pull/135)
from upstream commit `f4f124a02076ff2b4d0456fb040f04d2f1ab1906`.
This is an upstream command gap.

The port adds `-c N` and `--bytes=N` through the upstream `take(N)` and `tokio::io::copy` path.
The last `-n` or `-c` option selects the mode. Negative byte counts remain unsupported.
The local `Mediated` parameter and `legacy_count` parser stay in place.
The seven upstream `head_bytes_*` tests are copied unchanged.
The separate `mv -f` change in upstream issue #134 remains outside this port.

### Local command correctness: sed-carriage-returns

The vendored sed stripped carriage returns from the input pattern space. It now removes only the terminating newline, so carriage returns remain available to commands and output.
Regression coverage is in `tests/box_sed_carriage_returns.rs`.
