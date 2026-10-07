//! Experiments on the process cardinality of the Shell and Monty boundaries.
//!
//! **This suite is an experiment, not a contract.** Several tests below assert what the
//! box *currently does* — including behaviour that is arguably a defect — so that a
//! decision about cardinality is made against measurements rather than against
//! assumptions. Each test names which way it is pointing.
//!
//! The question that docs/design/decisions.md#no-state-crosses-a-call-boundary answers: does
//! the Shell need to be per-run rather than per-box, does either boundary need to be
//! bidirectional, and would a pinning mechanism make this more robust. What is measured here:
//!
//! | # | Experiment | What it decides |
//! |---|---|---|
//! | E1 | Shell session state across invocations, and across runs | whether one Shell per box is a shared mutable channel |
//! | E2 | Head-of-line blocking on the serial worker | whether one Shell per box is a liveness coupling |
//! | E3 | Temporal budget shared across runs | whether one history per box is attributable |
//! | E4 | Monty state across invocations | whether the per-request VM is a usability floor |
//! | E5 | Bidirectionality: stdin, and streamed output | whether request/reply can carry a real harness |
//! | E6 | Peer identity on the socket | whether pinning is even implementable today |
//!
//! Cardinality as built (verified by reading, pinned by the tests below):
//!
//! ```text
//! box              1 per name
//! daemon           1 per box          flock on live/.alive
//! PolicyEngine     1 per box          one Arc, cloned to three enforcement points
//! Shell            1 per box          serial worker, rebuilt on abandon or timeout
//! box.sock         1 per box          fixed path, public/run/box.sock; every interpreter
//! Monty VM         1 per REQUEST      built and dropped inside run_script
//! run (workload)   N per box          all sharing every row above
//! alias process    1 per command      exec'd by the workload, exits after one round trip
//! ```

use std::path::PathBuf;
use std::process::Output;
use std::time::Instant;

#[path = "support/fixture.rs"]
mod fixture;

use fixture::{Configured, Request};

/// Permits any command and any read, so every experiment below measures *cardinality*
/// rather than a policy denial.
const PERMISSIVE: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"fs:read", resource);
permit(principal, action == Box::Action::"fs:write", resource);
permit(principal, action == Box::Action::"fs:delete", resource);
permit(principal, action == Box::Action::"fs:move", resource);
"#;

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Fail loudly when a run never reached its workload.
///
/// Every experiment below that asserts a *negative* — no state carried, no stdin arriving,
/// a budget exhausted — is satisfied trivially by an empty stdout. A run that died before
/// exec'ing (a missing trampoline, a refused profile) produces exactly that, so without
/// this guard those tests report the conclusion they were written to test while measuring
/// nothing. Three of them did on the first run of this suite.
fn assert_workload_launched(output: &Output, what: &str) {
    let stderr = stderr(output);
    assert!(
        !stderr.contains("strands-box: error:"),
        "the run never reached its workload, so {what} measured nothing: {stderr}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// E1 — One Shell per REQUEST: no session state crosses, in either direction
// ═══════════════════════════════════════════════════════════════════════════════
//
// These three asserted the OPPOSITE until 2026-08-08, and that is the point of keeping
// them: they were the measurement that justified the change, and inverted they are the
// guard on it. Each `assert!` below was an `assert!` with the sense flipped, against the
// same script.

/// Two alias invocations in one run do NOT share session state.
///
/// Each `zsh -c` is its own process, its own connection, its own request — and now its own
/// `Shell`. So an `export` in the first is invisible to the second.
///
/// This is the cost of per-request, taken deliberately: no harness depends on the
/// continuity. Codex makes `workdir` **required** on every `shell` call; OpenClaw, Gemini,
/// and Claude Code all resolve cwd per call against a fresh process; and the harnesses that
/// do hold a persistent shell hold it in their own process, which this box cannot host
/// (`zsh -i` is refused — E5c).
#[test]
fn e1a_session_state_does_not_persist_across_invocations() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e1a", PERMISSIVE).expect();

    let output = box_.bash(
        r#"
        zsh -c "export CARRIED=first_invocation" >/dev/null
        zsh -c 'printf "carried=[%s]" "$CARRIED"'
        "#,
    );

    assert_workload_launched(&output, "E1a");
    assert!(
        stdout(&output).contains("carried=[]"),
        "one Shell per request means nothing carries between invocations. If this starts \
         carrying, the Shell became long-lived again, so update \
         docs/design/decisions.md#no-state-crosses-a-call-boundary. {output:?}"
    );
}

/// Session state does NOT leak from one run into the next.
///
/// The sharp one. Before the change, run B — a different contained process, launched by a
/// different `strands-box run` — read state that run A wrote. Two runs in one box are meant
/// to share *authority* (one policy, one proxy, one history, all deliberate); they were
/// never meant to share a mutable shell session, and nothing documented that they did.
#[test]
fn e1b_session_state_does_not_leak_between_runs() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e1b", PERMISSIVE).expect();

    let writer = box_.bash(r#"zsh -c "export LEAKED_ACROSS_RUNS=from_run_a""#);
    assert!(
        writer.status.success(),
        "the writing run must succeed: {writer:?}"
    );

    let reader = box_.bash(r#"zsh -c 'printf "leaked=[%s]" "$LEAKED_ACROSS_RUNS"'"#);

    assert_workload_launched(&reader, "E1b");
    assert!(
        stdout(&reader).contains("leaked=[]"),
        "a later run must NOT read an earlier run's shell session state. A failure here is \
         a cross-run channel reopening — the defect this change closed. reader={reader:?}"
    );
}

/// The working directory does not carry either, and resets to the box home.
///
/// Separate from the environment case because `cd` is what a coding harness does on almost
/// every turn, so it was the collision most likely to be hit. Asserts the positive too: a
/// fresh Shell starts at the box home's **host** path, which is what `ShellSpec::build` sets
/// `cwd`/`PWD`/`HOME` to — so a bare `cd` and `~` still land somewhere one `fs:*` rule
/// covers.
///
/// The reset is asserted by naming the home rather than by the absence of `/tmp`. The box home
/// is itself under `/tmp` in this fixture, so "does not contain `/tmp`" now fails on a correct
/// run — it was only ever true while the Shell fabricated a `/home/strands-box` mount.
#[test]
fn e1c_the_working_directory_does_not_carry_between_runs() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e1c", PERMISSIVE).expect();
    // The **workspace**, which is where the interpreters start. It was the box home until
    // 2026-08-18: the operator's policy names the workspace, so a relative path had to resolve
    // there. The property under test is unchanged — a `cd` in one run must not carry into the
    // next — and only the directory each run starts in moved.
    let start = box_.workspace().display().to_string();

    // `/tmp` exists in the Shell's own VFS, so this `cd` succeeds regardless of the host.
    let mover = box_.bash(r#"zsh -c "cd /tmp; pwd""#);
    assert!(
        mover.status.success(),
        "the moving run must succeed: {mover:?}"
    );
    assert_eq!(
        stdout(&mover).trim(),
        "/tmp",
        "the cd itself must work within its own command: {mover:?}"
    );

    let observer = box_.bash(r#"zsh -c "pwd""#);

    assert_workload_launched(&observer, "E1c");
    assert_eq!(
        stdout(&observer).trim(),
        start,
        "a later run must start at the workspace rather than inherit the earlier run's cwd, so a \
         relative path stays governed by one rule: {observer:?}"
    );
}
/// A slow request does not delay a concurrent one.
///
/// **Both requests come from ONE run, because one run owns a box.** The property was
/// never about runs: the box builds one Shell per *connection*, so two alias invocations from
/// one workload are what must not serialize. Timed with bash's own `SECONDS`, because the profile
/// grants exec on the workload and the five aliases and nothing else — there is no `date`.
#[test]
fn e2_a_slow_request_does_not_delay_a_concurrent_one() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e2", PERMISSIVE).expect();

    let output = box_.bash(
        r#"
zsh -c "sleep 6" &
zsh -c "sleep 2"
SECONDS=0
zsh -c "printf quick"
printf "|elapsed=%s" "$SECONDS"
"#,
    );

    eprintln!("E2 MEASURED: {:?}", stdout(&output));
    assert_workload_launched(&output, "E2's probe");
    assert!(
        stdout(&output).contains("quick"),
        "the probe must actually run its command: {output:?}"
    );
    let elapsed = elapsed_seconds(&stdout(&output));
    assert!(
        elapsed < 4,
        "EXPERIMENT E2: a concurrent request must NOT queue behind the sibling's sleep. \
         If this regresses, a serializing queue came back — check `serve`. elapsed={elapsed}s, \
         output={output:?}"
    );
}
/// A non-yielding request does not delay a concurrent one.
///
/// The Lua interpreter never awaits, so it once pinned the runtime every request
/// shared and an unrelated probe took 27.73s. Each connection owns its thread now. Both requests
/// come from one run, for the reason E2 states.
#[test]
fn e2b_a_non_yielding_request_does_not_delay_a_concurrent_one() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e2b", PERMISSIVE).expect();

    let output = box_.bash(
        r#"
zsh -c "lua -e 'while true do end'" &
zsh -c "sleep 3"
SECONDS=0
zsh -c "printf quick"
printf "|elapsed=%s" "$SECONDS"
"#,
    );

    eprintln!(
        "E2b MEASURED: {:?} (was 27.73s before each connection got its own thread)",
        stdout(&output)
    );
    assert_workload_launched(&output, "E2b's probe");
    assert!(
        stdout(&output).contains("quick"),
        "the probe must actually run its command: {output:?}"
    );
    let elapsed = elapsed_seconds(&stdout(&output));
    assert!(
        elapsed < 5,
        "EXPERIMENT E2b: a non-yielding command must pin its own thread and nobody else's. \
         If this regresses, the connections went back onto one shared runtime. elapsed={elapsed}s, \
         output={output:?}"
    );
}
/// One temporal history per box: shared across requests and durable across runs.
///
/// Within a run, every request meets one `PolicyEngine`. Across runs, each engine recovers the
/// same box-private database. Both paths must enforce one continuous temporal budget.
#[test]
fn e3_the_temporal_budget_is_shared_within_a_run_and_persists_into_the_next() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const CAP: usize = 4;
    let policy = format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when {{ context.input.command == "printf tick" }};
forbid(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when temporal {{
    exists (executed: Long). (
        (count for (t: Timepoint). where (
            formerly within 300s (
                Box::Action::"shell:exec"::response{{ input.command: _ }} && tp(t)
            )
        )) == executed
        && executed >= {CAP}
    )
}};
"#
    );
    let box_ = Request::with_policy("card-e3", &policy).expect();

    // A literal list, not `$(seq 1 N)`: `seq` is an external binary and the profile grants exec
    // on the workload plus the aliases and nothing else, so a substitution yields nothing and the
    // loop runs zero times. That is how this experiment once reported a conclusion having
    // executed no commands at all.
    let spend = (1..=CAP)
        .map(|_| r#"zsh -c "printf tick"; printf "\n";"#.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let within = box_.bash(&format!(
        r#"{spend} zsh -c "printf tick"; printf "|status=%s" "$?""#
    ));
    eprintln!("E3 within one run: {:?}", stdout(&within));
    assert_workload_launched(&within, "E3's in-run probe");
    assert!(
        !stdout(&within).contains("tick|status=0"),
        "EXPERIMENT E3: the {CAP}th request must exhaust the budget for the NEXT request in the \
         same run. If this fails, history became per connection, so update \
         docs/design/decisions.md#no-state-crosses-a-call-boundary. \
         within={within:?}"
    );

    // A second run opens a new engine over the same box-private database.
    let next = box_.bash(r#"zsh -c "printf tick"; printf "|status=%s" "$?""#);
    eprintln!("E3 next run: {:?}", stdout(&next));
    assert_workload_launched(&next, "E3's next run");
    assert!(
        !stdout(&next).contains("tick|status=0"),
        "EXPERIMENT E3: a new `PolicyEngine` must recover the previous run's spending. \
         If this fails, durable history did not cross the run boundary. next={next:?}"
    );
}

/// Read `|elapsed=<n>` out of a probe's stdout.
fn elapsed_seconds(stdout: &str) -> u64 {
    stdout
        .rsplit_once("|elapsed=")
        .map(|(_, tail)| tail.trim())
        .and_then(|tail| {
            tail.split(|c: char| !c.is_ascii_digit())
                .next()
                .filter(|digits| !digits.is_empty())
        })
        .unwrap_or_else(|| panic!("the probe must report its elapsed seconds: {stdout:?}"))
        .parse()
        .expect("elapsed seconds parse")
}

// ═══════════════════════════════════════════════════════════════════════════════
// E4 — Monty is the opposite choice: one VM per request, so no state at all
// ═══════════════════════════════════════════════════════════════════════════════

/// Python state does NOT persist across invocations, in either direction.
///
/// The mirror image of E1. Monty builds a VM inside `run_script` and drops it, which the
/// module documents as a deliberate refusal to carry interpreter state between separately
/// judged requests. So Monty has no cross-run channel and no continuity: `x = 1` in one
/// invocation is a `NameError` in the next.
///
/// The two boundaries therefore sit at opposite ends of the same axis.
#[test]
fn e4_monty_carries_no_state_between_invocations() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e4", PERMISSIVE).expect();

    let output = box_.bash(
        r#"
        python3 -c "CARRIED = 'first'" >/dev/null 2>&1
        python3 -c "print('carried=' + CARRIED)" 2>&1
        printf "|status=%s" "$?"
        "#,
    );

    let text = stdout(&output);
    eprintln!("E4 monty: {text:?} stderr={:?}", stderr(&output));
    assert_workload_launched(&output, "E4");
    assert!(
        !text.contains("carried=first"),
        "EXPERIMENT E4: a fresh VM per request means no state crosses. \
         If this ever carries, Monty started reusing a VM, so update \
         docs/design/decisions.md#no-state-crosses-a-call-boundary. output={output:?}"
    );
}

/// A fresh undefined name reports a Python `NameError`, not a broker failure.
///
/// Monty suspends on an unresolved name (`RunProgress::NameLookup`), which `drive_monty` now
/// resolves as `Undefined` — so the VM raises a catchable `NameError` and the script exits `1`,
/// the same as CPython. The broker-failure status `125` stays reserved for *the boundary broke*,
/// so a typo and a box-level fault no longer report the same thing.
///
/// Measured against a *fresh* undefined name, so this is not confounded with E4's cross-request
/// question: there is no previous request here at all.
#[test]
fn e4c_an_undefined_name_is_reported_as_a_python_error() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e4c", PERMISSIVE).expect();

    let output = box_.bash(r#"python3 -c "print(NEVER_DEFINED)" 2>&1; printf "|status=%s" "$?""#);

    let text = stdout(&output);
    eprintln!("E4c undefined name: {text:?} stderr={:?}", stderr(&output));
    assert_workload_launched(&output, "E4c");
    assert!(
        text.contains("NameError") && text.contains("|status=1"),
        "E4c: an undefined name is a Python NameError at status 1, not a broker failure. \
         output={output:?}"
    );
}

/// Two concurrent Python scripts do run concurrently at the connection level.
///
/// Monty's `serve` spawns each connection into a `JoinSet` rather than feeding one worker,
/// so the capacity is 8. What that does *not* buy is concurrent decision-making — all
/// three enforcement points share one `PolicyEngine` behind one mutex — which is why this
/// measures rather than asserts a speedup.
#[test]
fn e4b_concurrent_python_requests_are_admitted() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e4b", PERMISSIVE).expect();

    let start = Instant::now();
    let output = box_.bash(
        r#"
        for i in 1 2 3 4; do python3 -c "print($i * 11)" & done
        wait
        "#,
    );
    let elapsed = start.elapsed();

    let text = stdout(&output);
    eprintln!("E4b MEASURED: four concurrent scripts in {elapsed:?}; output={text:?}");
    for expected in ["11", "22", "33", "44"] {
        assert!(
            text.contains(expected),
            "every concurrent script must be answered; missing {expected}: {output:?}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// E5 — Bidirectionality: what request/reply cannot carry
// ═══════════════════════════════════════════════════════════════════════════════

/// The alias forwards no stdin, so a command that reads gets nothing.
///
/// `ShellRequest` carries `version` and `command` and nothing else, and the alias closes
/// every descriptor above stdio before connecting. So there is no channel for input at
/// all — not an empty one, none.
///
/// This was the concrete blocker behind an MCP-over-stdio plan: an MCP server is a bidirectional
/// stdio session, and version 1 of this protocol has no frame that could carry one.
///
/// The decision that answers it is docs/design/decisions.md#a-box-is-one-kernel-and-many-programs.
/// The blocker is now lifted for the *transport* protocol (version 2), which carries in-band stdin
/// and many frames per connection; this test pins version 1's behaviour, which is unchanged and
/// still what the alias speaks.
#[test]
fn e5a_no_stdin_reaches_a_shell_command() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e5a", PERMISSIVE).expect();

    let output = box_.bash(
        r#"printf "from_workload_stdin" | zsh -c 'read LINE; printf "read=[%s]" "$LINE"'; printf "|status=%s" "$?""#,
    );

    let text = stdout(&output);
    eprintln!("E5a stdin: {text:?} stderr={:?}", stderr(&output));
    assert_workload_launched(&output, "E5a");
    assert!(
        !text.contains("read=[from_workload_stdin]"),
        "EXPERIMENT E5a: the protocol carries no stdin, so a piped value cannot arrive. \
         If this ever passes, the protocol gained an input channel, so update \
         docs/design/decisions.md#no-state-crosses-a-call-boundary. \
         output={output:?}"
    );
}

/// Output reaches the workload while the command is still running.
///
/// **Inverted 2026-08-09.** This asserted the opposite — that nothing was observable until a
/// command finished — and its own failure message said "if this drops below the sleep, streaming
/// was added". Streaming was added, so the assertion is now the other way round.
///
/// Measured *inside* the workload, not around `strands-box run`. The outer process cannot return
/// before its workload exits, so an end-to-end timing here would sit at the sleep whether or not
/// output streamed — which is exactly why the old version kept passing after streaming landed. The
/// workload times its own first byte instead.
#[test]
fn e5b_output_streams_before_the_command_ends() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const SLEEP_SECONDS: u64 = 5;
    let box_ = Request::with_policy("card-e5b", PERMISSIVE).expect();

    // `date +%s` before and after the first line of output, inside the box. `zsh` writes EARLY at
    // t=0 then sleeps, so a streaming boundary yields the line immediately and a buffering one
    // yields it only at the end.
    let output = box_.bash(&format!(
        r#"start=$(date +%s)
           zsh -c "printf 'EARLY\n'; sleep {SLEEP_SECONDS}" | {{
               IFS= read -r first
               echo "first_byte_after=$(( $(date +%s) - start ))"
               echo "first_line=$first"
           }}"#
    ));

    let text = stdout(&output);
    eprintln!("E5b MEASURED: {text}");
    assert!(
        text.contains("first_line=EARLY"),
        "the first line must be what the command printed first: {output:?}"
    );
    // Strictly less than the sleep: the byte was produced at t=0, so anything at or past the sleep
    // means it was withheld until the command ended.
    let seconds: u64 = text
        .lines()
        .find_map(|line| line.strip_prefix("first_byte_after="))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("the workload must report its own timing: {output:?}"));
    assert!(
        seconds < SLEEP_SECONDS,
        "EXPERIMENT E5b: output must reach the workload before the command ends. \
         If this ever rises to the sleep, streaming regressed to buffering. \
         first_byte_after={seconds}s, sleep={SLEEP_SECONDS}s"
    );
}

/// An interactive spelling is refused outright rather than degraded.
///
/// `zsh -i` has no meaning against a request/reply boundary, and the alias says so instead
/// of opening a file named `-i`. Recorded here because "does it need to be bi-di" is
/// partly a question about what the box currently tells a harness that wants one.
#[test]
fn e5c_an_interactive_shell_is_refused() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e5c", PERMISSIVE).expect();

    let output = box_.bash(r#"zsh -i </dev/null; printf "|status=%s" "$?""#);

    eprintln!(
        "E5c interactive: stdout={:?} stderr={:?}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("accepts only") || stdout(&output).contains("|status=125"),
        "an interactive request must be refused with a reason: {output:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// E6 — Is pinning implementable? What identity does a connection actually carry
// ═══════════════════════════════════════════════════════════════════════════════

/// Every run reaches the same socket path, so the path cannot identify a run.
///
/// The alias derives its socket from its own grandparent, and both the alias image and the
/// socket are box-lifetime — placed by `create`, not by a run. So two concurrent runs
/// exec the *same* alias file and connect to the *same* socket. Any pinning mechanism has
/// to come from the connection, not the path.
///
/// Directly relevant to the pinning question: this is why per-run scoping cannot be
/// done by giving each run its own socket without changing what `create` materializes.
#[test]
fn e6_concurrent_runs_share_one_alias_image_and_one_socket() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e6", PERMISSIVE).expect();

    // Each run reports the socket its own alias would derive, from its own PATH.
    let script = r#"
        BIN=${PATH##*:}
        ROOT=${BIN%/bin}
        printf "alias=%s|socket=%s|inode=" "$BIN/zsh" "$ROOT/run/box.sock"
        zsh -c "printf shell_reached"
    "#;

    let first = box_.bash(script);
    let second = box_.bash(script);

    let first_text = stdout(&first);
    let second_text = stdout(&second);
    eprintln!("E6 run1: {first_text:?}");
    eprintln!("E6 run2: {second_text:?}");

    assert_eq!(
        first_text, second_text,
        "EXPERIMENT E6: two runs see an identical alias path and socket path, so neither \
         identifies the run. Any pinning must derive from the connection."
    );
    assert!(
        first_text.contains("shell_reached"),
        "both runs must actually reach the Shell: {first:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// E7 — Does a REAL alias, inside containment, carry its run's identity?
// ═══════════════════════════════════════════════════════════════════════════════

/// Read the identities the daemon's probe recorded for each boundary connection.
///
/// **Depends on the cardinality experiment scaffolding in `shell/host.rs`.** If that probe has
/// been removed (as it must be before any merge), this returns empty and the test skips
/// rather than failing — the scaffolding is the experiment, not a contract.
fn probed_identities(box_: &Configured) -> Vec<(i32, i32)> {
    // The log sits at the **machine** root, not under any box's `private/`. This read
    // `<box root>/private/live/daemon.log`, a path nothing writes, so `unwrap_or_default` returned
    // empty text and the caller skipped every time — a check that could not fail.
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|declared| declared.is_absolute())
        .unwrap_or_else(|| box_.operator_home().join(".local").join("state"));
    let log = state.join("strands-box").join("daemon.log");
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    text.lines()
        .filter_map(|line| line.strip_prefix("KD12-PROBE: peer_pid="))
        .filter_map(|rest| {
            let mut fields = rest.split_whitespace();
            let pid = fields.next()?.parse().ok()?;
            let group = fields.next()?.strip_prefix("peer_pgid=")?.parse().ok()?;
            Some((pid, group))
        })
        .collect()
}

/// Two runs' aliases reach the daemon under two different process groups.
///
/// The end-to-end version of `box_pinning_feasibility.rs` P2, and the one that settles
/// whether pinning is *implementable here* rather than merely possible on a socket. The
/// alias is exec'd through the trampoline inside a Seatbelt domain, so the question is
/// whether the run's process group survives that launch path and is visible to the daemon.
///
/// If it does: a per-run Shell session, a per-run temporal budget, or a per-run capability
/// can be keyed server-side with no change to the wire protocol and no cooperation from the
/// contained workload — which is the cheapest shape any pinning mechanism could take.
#[test]
fn e7_a_real_alias_carries_its_runs_process_group_to_the_daemon() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e7", PERMISSIVE).expect();

    let first = box_.bash(r#"zsh -c "printf run_one""#);
    let second = box_.bash(r#"zsh -c "printf run_two""#);
    assert_workload_launched(&first, "E7's first run");
    assert_workload_launched(&second, "E7's second run");

    let identities = probed_identities(&box_);
    if identities.is_empty() {
        eprintln!(
            "E7 SKIPPED: the cardinality probe in shell/host.rs is absent, so there is nothing \
             to read. This is the expected state on any branch that removed the scaffolding."
        );
        return;
    }

    eprintln!("E7 MEASURED: (peer_pid, peer_pgid) per boundary connection = {identities:?}");
    assert!(
        identities.len() >= 2,
        "both runs must have reached the Shell: {identities:?}"
    );
    let groups: Vec<i32> = identities.iter().map(|(_, group)| *group).collect();
    let first_group = groups[0];
    let last_group = *groups.last().unwrap();
    assert_ne!(
        first_group, last_group,
        "EXPERIMENT E7: two runs must present two process groups for per-run keying to be \
         implementable server-side. If these are equal, the run's group does not survive \
         the trampoline and pinning needs a different identity, so update \
         docs/design/decisions.md#no-state-crosses-a-call-boundary. \
         groups={groups:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// E8 — Two defects the per-request VM's usability rests on (not cardinality)
// ═══════════════════════════════════════════════════════════════════════════════

/// Unimplemented builtins report the BOUNDARY-BROKE status, not a Python error.
///
/// Widens E4c to unresolved *callables*. Monty auto-injects an `ExtFunction`
/// for any unresolved callable name, so calling one suspends as a `FunctionCall` rather than
/// raising. `drive_monty` now resolves each non-`fetch` `FunctionCall` as `NotFound`, so the VM
/// raises a catchable `NameError` and the script exits `1`, the same as an undefined bare name.
///
/// Measured: a typo'd builtin, `memoryview()`, `input()`, and `__import__()` all report a Python error
/// at status 1, matching `import subprocess`'s own `ModuleNotFoundError`. The boundary-broke
/// status `125` no longer appears for a language error.
#[test]
fn e8a_unimplemented_builtins_report_a_python_error() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e8a", PERMISSIVE).expect();

    for source in [
        r#"print(NEVER_DEFINED)"#,
        r#"prnt(1)"#,
        r#"memoryview(b\"x\")"#,
        r#"input()"#,
        r#"__import__(\"os\")"#,
    ] {
        let output = box_.bash(&format!(
            r#"python3 -c "{source}" 2>&1; printf "|st=%s" "$?""#
        ));
        assert_workload_launched(&output, "E8a");
        let text = stdout(&output);
        eprintln!("E8a {source:?} -> {text:?}");
        assert!(
            text.contains("NameError") && text.contains("|st=1"),
            "E8a: `{source}` is a Python error at status 1, not a broker failure. output={output:?}"
        );
    }

    // The contrast: Monty's OWN error path reports status 1 with a Python exception name.
    let controlled = box_.bash(r#"python3 -c "import subprocess" 2>&1; printf "|st=%s" "$?""#);
    let text = stdout(&controlled);
    eprintln!("E8a control (import subprocess) -> {text:?}");
    assert!(
        text.contains("ModuleNotFoundError") && text.contains("|st=1"),
        "the control must show Monty reporting a real Python error: {controlled:?}"
    );
}

/// `open(path, "w")` issues a handle, and a `write` on it now performs.
///
/// A handle write routes through `AppendText`, and `perform` implements that arm now. So the
/// write completes on the policy-approved, canonical path in the box home, where it once refused
/// with `RuntimeError: Path.append_text: not supported`.
/// `Path.write_text` performs the same way.
///
/// Bears on cardinality: a fresh VM per request runs ordinary file writes.
#[test]
fn e8b_an_opened_file_is_written_through() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e8b", PERMISSIVE).expect();
    let home_path = box_.box_home();
    let home = home_path.display();

    // The one-shot spelling, as a contrast that shares the same floor and policy.
    let works = box_.bash(&format!(
        r#"python3 -c "
from pathlib import Path
Path('{home}/wt.txt').write_text('ok')
print('write_text ok')" 2>&1; printf "|st=%s" "$?""#
    ));
    assert_workload_launched(&works, "E8b's control");
    eprintln!("E8b write_text -> {:?}", stdout(&works));
    assert!(
        stdout(&works).contains("write_text ok"),
        "the control must succeed, else this measures the floor rather than perform: \
         {works:?}"
    );

    let opened = box_.bash(&format!(
        r#"python3 -c "
f = open('{home}/ow.txt', 'w')
f.write('hello')
print('open+write ok')" 2>&1; printf "|st=%s" "$?""#
    ));
    assert_workload_launched(&opened, "E8b");
    let text = stdout(&opened);
    eprintln!("E8b open+write -> {text:?}");
    assert!(
        text.contains("open+write ok") && text.contains("|st=0"),
        "an opened file is written through now that `perform` implements the `AppendText` \
         arm (docs/design/decisions.md#monty-performs-only-effects-the-box-can-govern); \
         this once refused with `append_text: not supported`. \
         output={opened:?}"
    );
    assert!(
        std::fs::read_to_string(home_path.join("ow.txt")).is_ok_and(|body| body.contains("hello")),
        "the write must have reached the box home: {opened:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// E9 — Bind mode: the box's bind is a pass-through, and a refusal says why
// ═══════════════════════════════════════════════════════════════════════════════

/// The Shell's bind is a live pass-through to the host, not a copy.
///
/// `strands-shell` has two bind modes — `BindMode::Copy` (the builder's `bind`/`bind_readonly`,
/// which calls `copy_from_host` and snapshots bytes *into* the VFS) and `BindMode::Direct`
/// (`bind_direct*`, which stores the host path in `InodeData::HostFile`/`HostDir` and resolves
/// it at operation time). The box uses **Direct**, so this asserts the observable difference a
/// copy could not produce: a file created on the host *after* the daemon started is visible,
/// and a host edit to an existing file is seen live.
///
/// Worth pinning because `Copy` is the *default* for a `BindEntry` (`default_mode`), so a
/// future change that reached for `bind`/`bind_readonly` instead of `bind_direct*` would
/// silently snapshot the workspace and every later host change would be invisible.
#[test]
fn e9a_the_bind_passes_through_to_the_host_rather_than_copying() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e9a", PERMISSIVE).expect();
    let home = box_.box_home();

    // Written after `create` started the daemon, so a build-time copy cannot contain it.
    std::fs::write(home.join("host-late.txt"), "created-after-daemon-start").expect("host write");

    // The Shell names the box home by its **host** path, so the command spells the
    // same string the workload's own `HOME` holds.
    let named = home.display();

    let appeared = box_.bash(&format!(r#"zsh -c "cat {named}/host-late.txt""#));
    assert_workload_launched(&appeared, "E9a");
    assert!(
        stdout(&appeared).contains("created-after-daemon-start"),
        "a Direct bind must show a file the host created after startup; a Copy bind could \
         not: {appeared:?}"
    );

    // And an edit to a file the Shell has already read must be seen, not the stale bytes.
    std::fs::write(home.join("edit.txt"), "v1").expect("host write");
    let first = box_.bash(&format!(r#"zsh -c "cat {named}/edit.txt""#));
    assert!(stdout(&first).contains("v1"), "{first:?}");
    std::fs::write(home.join("edit.txt"), "v2-edited-on-host").expect("host rewrite");

    let second = box_.bash(&format!(r#"zsh -c "cat {named}/edit.txt""#));
    assert!(
        stdout(&second).contains("v2-edited-on-host"),
        "a Direct bind resolves the host path per operation, so an edit must be visible: \
         {second:?}"
    );
}

/// A write refused through a REDIRECT says *why*, not just exit non-zero.
///
/// Regression guard on a defect in the vendored shell's `exec.rs`, found while establishing
/// that the bind passes through. Its single-builtin path calls `set_err_tx` to route
/// `err_msg` into a channel, then returns on a redirect failure *before* spawning the task
/// that drains it — so the message went into a receiver nobody read, and the failure surfaced
/// as a bare status with **empty stderr**. `clear_err_tx` before reporting sends it to the
/// shell's captured stderr instead.
///
/// It was found against a read-only bind (`printf x > <ro-path>` was silent while `tee` and
/// `mkdir` printed "read-only bind mount"), which read exactly like "the bind silently
/// swallows writes" and was not that at all. **The bind is writable now** — policy decides a
/// write (E10a/E10b) — so this asserts the same reporting path with a *policy* denial, which
/// is what a redirect refusal means today. Deny-and-teach depends on it: a denial that names
/// no rule tells an author nothing about what to add.
#[test]
fn e9b_a_refused_redirect_reports_its_reason() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const NO_WRITE_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"fs:read", resource);
"#;
    let box_ = Request::with_policy("card-e9b", NO_WRITE_POLICY).expect();
    let home = box_.box_home();
    let named = home.display();

    for (spelling, script) in [
        ("redirect", format!(r#"zsh -c "printf x > {named}/a.txt""#)),
        ("tee", format!(r#"zsh -c "printf x | tee {named}/b.txt""#)),
        ("mkdir", format!(r#"zsh -c "mkdir {named}/d""#)),
    ] {
        let output = box_.bash(&format!(r#"{script}; printf "|status=%s" "$?""#));
        assert_workload_launched(&output, "E9b");
        let combined = format!("{}{}", stdout(&output), stderr(&output));
        eprintln!("E9b {spelling}: {combined:?}");
        assert!(
            combined.contains("policy denied"),
            "the {spelling} spelling must name the reason, not just exit non-zero: {output:?}"
        );
        assert!(
            stdout(&output).contains("|status=1"),
            "the {spelling} spelling must fail: {output:?}"
        );
    }

    // The control, and it is load-bearing: a *permitted* redirect must still succeed, and
    // promptly. A first attempt at the fix cloned the sender instead of clearing it, which
    // left a sender alive on the success path — `err_rx` never reached end-of-stream and
    // every redirect hung until the 30s command deadline. Measured. The success path is
    // therefore what guards the fix, not the failure path.
    //
    // A second box, because this one deliberately withholds `fs:write`.
    let permitted = Request::with_policy("card-e9b-ok", PERMISSIVE).expect();
    let start = Instant::now();
    let writable = permitted.bash(r#"zsh -c "printf ok > /tmp/c.txt; cat /tmp/c.txt""#);
    let elapsed = start.elapsed();
    assert!(
        stdout(&writable).contains("ok"),
        "a permitted redirect must still succeed: {writable:?}"
    );
    assert!(
        elapsed.as_secs() < 10,
        "a successful redirect must not wait on an undrained channel: took {elapsed:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// E10 — Shell/Monty write parity: one policy rule, one meaning
// ═══════════════════════════════════════════════════════════════════════════════

/// The same `permit fs:write` lets BOTH boundaries write the same directory.
///
/// The parity fix. The Shell's bind was `bind_direct_readonly`, so a write was refused by
/// the *mount* before policy was consulted — measured: with an identical policy, Monty wrote
/// to the box home and succeeded while the Shell got `read-only bind mount`. One rule, two
/// boundaries, two meanings.
///
/// It also produced a phantom: a Shell "write" to its VFS `/tmp` succeeded and was readable
/// back, while existing nowhere the workload, Monty, or the host could see.
///
/// Both now land in the same real host directory, which is what makes an `fs:*` rule mean
/// one thing.
#[test]
fn e10a_both_boundaries_write_the_same_directory_under_one_policy() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e10a", PERMISSIVE).expect();
    let home = box_.box_home();

    // One spelling for both boundaries, which is the parity this test is about: the Shell
    // names the home by the same host path Monty does.
    let shell = box_.bash(&format!(
        r#"zsh -c "printf shell-wrote > {}/s.txt""#,
        home.display()
    ));
    assert_workload_launched(&shell, "E10a's Shell write");
    assert!(
        !stderr(&shell).contains("read-only bind mount"),
        "the Shell's write must be policy's decision, not the mount's: {shell:?}"
    );

    let monty = box_.bash(&format!(
        r#"python3 -c "
from pathlib import Path
Path('{}/m.txt').write_text('monty-wrote')
print('ok')" 2>&1"#,
        home.display()
    ));
    assert_workload_launched(&monty, "E10a's Monty write");

    // The point: both are real files, in one directory, on the host.
    let shell_landed = std::fs::read_to_string(home.join("s.txt")).unwrap_or_default();
    let monty_landed = std::fs::read_to_string(home.join("m.txt")).unwrap_or_default();
    eprintln!("E10a host: s.txt={shell_landed:?} m.txt={monty_landed:?}");
    assert_eq!(
        shell_landed, "shell-wrote",
        "the Shell's write must reach the host, not a phantom VFS: shell={shell:?}"
    );
    assert_eq!(
        monty_landed, "monty-wrote",
        "Monty's write must reach the same directory: monty={monty:?}"
    );
}

/// With `fs:write` withheld, POLICY denies both boundaries — and nothing is written.
///
/// The converse of E10a, and the reason relaxing the mount is safe rather than a widening:
/// the mount no longer refuses writes, so this proves *something still does*. A regression
/// here would mean the box had traded a parity defect for an unconditional write grant.
///
/// The Shell reports the rule (`policy denied … <default-deny>`), which is the deny-and-teach
/// behavior a read-only mount could never produce — it said "read-only bind mount", which
/// tells an author nothing about which rule to add.
#[test]
fn e10b_withholding_fs_write_denies_both_boundaries() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const READ_ONLY_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"fs:read", resource);
"#;
    let box_ = Request::with_policy("card-e10b", READ_ONLY_POLICY).expect();
    let home = box_.box_home();

    let shell = box_.bash(&format!(r#"zsh -c "printf x > {}/s.txt""#, home.display()));
    assert_workload_launched(&shell, "E10b's Shell write");
    assert!(
        stderr(&shell).contains("policy denied"),
        "policy must be what refuses the Shell's write, and must say so: {shell:?}"
    );

    let monty = box_.bash(&format!(
        r#"python3 -c "
from pathlib import Path
Path('{}/m.txt').write_text('x')
print('ok')" 2>&1"#,
        home.display()
    ));
    assert_workload_launched(&monty, "E10b's Monty write");
    assert!(
        stdout(&monty).contains("policy denied"),
        "policy must refuse Monty's write too: {monty:?}"
    );

    for name in ["s.txt", "m.txt"] {
        assert!(
            !home.join(name).exists(),
            "a denied write must not land: {name} exists"
        );
    }
}

/// The floor is the DENY FLOOR now, and policy still cannot widen it.
///
/// The workload cannot reach the operator's home directly. The policy-controlled interpreter can,
/// so a permissive policy lets the Shell read a file there.
///
/// What protects the operator instead is that absent policy denies and the starter policy scopes
/// `fs:read` to the workspace. A `permit` on everything is an operator choosing to grant everything.
///
/// **What did NOT change is the floor beneath policy.** No box's private tree is reachable and
/// neither is trusted Box state, whatever a rule says — this box's stored policy included. That
/// is `Reach`'s deny floor, and a `permit` cannot open it. This test is the guard on that half.
#[test]
fn e10c_policy_cannot_widen_the_mount_scope() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("card-e10c", PERMISSIVE).expect();
    let operator_home = box_.operator_home().to_path_buf();
    let secret = operator_home.join("operator-secret.txt");
    std::fs::write(&secret, "OPERATOR-ONLY").expect("plant an operator-owned file");
    let stored_policy = box_.root().join("private/policy.dw");

    // The interpreter can reach the operator's file under permissive policy. The workload cannot
    // reach it directly.
    let permitted = box_.bash(&format!(r#"zsh -c "cat {}" 2>&1"#, secret.display()));
    assert_workload_launched(&permitted, "E10c's permitted read");
    assert!(
        stdout(&permitted).contains("OPERATOR-ONLY"),
        "a permissive policy lets the interpreter reach the operator's own home: \
         {permitted:?}"
    );

    {
        let what = "the box's stored policy";
        let path = stored_policy.display().to_string();
        let shell = box_.bash(&format!(r#"zsh -c "cat {path}" 2>&1"#));
        assert_workload_launched(&shell, "E10c's Shell read");
        assert!(
            !stdout(&shell).contains("OPERATOR-ONLY") && !stdout(&shell).contains("permit("),
            "the Shell must not reach {what} even under a permissive policy: {shell:?}"
        );

        let monty = box_.bash(&format!(
            r#"python3 -c "
from pathlib import Path
print(Path('{path}').read_text())" 2>&1"#
        ));
        assert_workload_launched(&monty, "E10c's Monty read");
        let refused = stdout(&monty);
        assert!(
            refused.contains("trusted Box state") || refused.contains("Permission denied"),
            "Monty must refuse {what} beneath the box-root floor: {monty:?}"
        );
        assert!(
            !refused.contains("OPERATOR-ONLY") && !refused.contains("permit("),
            "the refusal must withhold the content of {what}: {monty:?}"
        );
    }
}
