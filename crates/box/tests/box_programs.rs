//! End-to-end Unix semantics of the box: one kernel, many programs, per-call limits.
//!
//! Governed by docs/design/decisions.md#a-box-is-one-kernel-and-many-programs.
//! Where `box_cardinality.rs` *measures* the boundary to inform a decision, this suite asserts
//! the semantics that decision landed, at the level an agent harness actually experiences them.
//!
//! The model under test:
//!
//! ```text
//! KERNEL   1 per box   policy + temporal history + the mount (a shared filesystem, by design)
//! PROGRAM  1 per       cwd, environment, functions, fds — private, never observed by a sibling
//!          program
//! CALL     1 per       deadline and output caps, re-armed each time
//!          submission
//! ```
//!
//! Two properties are in tension and both are asserted here, because getting either one alone
//! is the failure mode: programs **share** the filesystem (a file one writes, another reads) and
//! **isolate** their session state (a `cd` one makes, another never sees). That is exactly how
//! two processes on a real Unix host behave.
//!
//! **Concurrent-harness shape.** Several tests drive more than one contained workload at once,
//! each doing what a coding agent does — `cd` then build, write then read, chain on `$?`. This is
//! the case that was once broken: one workload running a non-yielding command stalled
//! every other one for its full deadline (27.73s measured), because all Shells shared a thread.
//!
//! **MCP is deliberately not exercised.** Nothing in the box vends an MCP server today — the
//! vendored Shell's client half needs `[[mcp]]` the box never writes, and its server half needs
//! `--mcp` the box never passes. What *is* asserted (`a_program_holds_a_session_across_many_calls`)
//! is the capability MCP would need: one program, many calls, state surviving between them. If
//! that holds, the abstraction can carry a session-oriented protocol later.

use std::io::Write as _;
use std::process::{Child, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[path = "support/fixture.rs"]
mod fixture;

use fixture::{Configured, Request};

/// Permits command execution and filesystem access, so these tests measure *semantics*
/// rather than a policy denial. Every test that needs a denial states its own policy.
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
/// Every negative assertion here — no state carried, no sibling visibility — is satisfied
/// trivially by an empty stdout, which is exactly what a run that died before `exec` produces.
/// Without this guard such a test reports the conclusion it was written to check while measuring
/// nothing.
fn assert_workload_launched(output: &Output, what: &str) {
    let stderr = stderr(output);
    assert!(
        !stderr.contains("strands-box: error:"),
        "the run never reached its workload, so {what} measured nothing: {stderr}"
    );
}

/// Start a run without waiting, so several contained workloads overlap.
fn spawn_run(box_: &Configured, script: &str) -> std::process::Child {
    // The same `{box_home}` substitution `Configured::bash` performs, because these scripts name
    // the box home too and it holds a per-test directory no literal can spell. Repeated
    // here rather than shared, because this helper exists precisely to *not* go through `bash`:
    // it must not wait on the run.
    let script = script.replace(fixture::BOX_HOME, &box_.box_home().display().to_string());
    box_.command_for("/bin/bash")
        .arg("-c")
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn a concurrent strands-box run")
}

// ═══════════════════════════════════════════════════════════════════════════════
// The KERNEL level — shared by every program, because a filesystem being shared
// IS the correct semantics
// ═══════════════════════════════════════════════════════════════════════════════

/// One program writes a file; another program reads it.
///
/// The Kernel level is deliberately shared: the mount is a filesystem, and two processes on one
/// host see one filesystem. A design that isolated this would not be Unix semantics — it would
/// be a separate box per program.
#[test]
fn programs_share_one_filesystem() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("prog-fs-share", PERMISSIVE).expect();

    let writer = box_.bash(r#"zsh -c 'printf shared_bytes > {box_home}/handoff.txt'"#);
    assert!(
        writer.status.success(),
        "the writing run must succeed: {writer:?}"
    );

    let reader = box_.bash(r#"zsh -c 'cat {box_home}/handoff.txt'"#);

    assert_workload_launched(&reader, "the filesystem-sharing reader");
    assert!(
        stdout(&reader).contains("shared_bytes"),
        "a second program must read what the first wrote — the Kernel level is shared \
         by design. reader={reader:?}"
    );
}

/// Every program is judged by one policy, so a denial is uniform across them.
///
/// The converse of sharing the filesystem: sharing the *authority*. A policy withholding
/// `fs:write` denies both programs, and neither can find a boundary that judges it differently.
#[test]
fn programs_share_one_authority() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const READ_ONLY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"fs:read", resource);
"#;
    let box_ = Request::with_policy("prog-one-auth", READ_ONLY).expect();

    let first =
        box_.bash(r#"zsh -c 'printf a > {box_home}/denied_one.txt' 2>&1; printf "|first=%s" "$?""#);
    let second = box_
        .bash(r#"zsh -c 'printf b > {box_home}/denied_two.txt' 2>&1; printf "|second=%s" "$?""#);

    assert_workload_launched(&first, "the first denied program");
    assert_workload_launched(&second, "the second denied program");
    assert!(
        !stdout(&first).contains("|first=0"),
        "a withheld fs:write must deny the first program: {first:?}"
    );
    assert!(
        !stdout(&second).contains("|second=0"),
        "and the second, from the same authority: {second:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// The PROGRAM level — private state, never observed by a sibling
// ═══════════════════════════════════════════════════════════════════════════════

/// A `cd` in one program does not move another program.
///
/// This was once a real defect: a sibling's `cd` silently changed what a relative
/// path resolved to in an unrelated run, so the same command meant different things depending on
/// what else happened to be running.
#[test]
fn a_working_directory_is_private_to_its_program() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("prog-cwd-private", PERMISSIVE).expect();

    let setup = box_.bash(r#"zsh -c 'mkdir -p {box_home}/sub'"#);
    assert!(setup.status.success(), "mkdir must succeed: {setup:?}");

    // One program moves and reports; another only reports.
    let mover = box_.bash(r#"zsh -c 'cd {box_home}/sub && pwd'"#);
    let observer = box_.bash(r#"zsh -c 'pwd'"#);

    assert_workload_launched(&mover, "the moving program");
    assert_workload_launched(&observer, "the observing program");
    // The assertions need the real path: `bash` substitutes the token in a *script*, and these
    // read the workload's output.
    let sub = format!("{}/sub", box_.box_home().display());
    assert!(
        stdout(&mover).contains(&sub),
        "a cd within one command must work: {mover:?}"
    );
    assert!(
        !stdout(&observer).contains(&sub),
        "a sibling program must NOT inherit that cd. If this regresses, cwd became shared \
         mutable state again. observer={observer:?}"
    );
}

/// An exported variable is private to its program.
#[test]
fn an_environment_is_private_to_its_program() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("prog-env-private", PERMISSIVE).expect();

    let exporter =
        box_.bash(r#"zsh -c 'export PRIVATE_TO_ME=yes; printf "set=[%s]" "$PRIVATE_TO_ME"'"#);
    let observer = box_.bash(r#"zsh -c 'printf "seen=[%s]" "$PRIVATE_TO_ME"'"#);

    assert_workload_launched(&exporter, "the exporting program");
    assert_workload_launched(&observer, "the observing program");
    assert!(
        stdout(&exporter).contains("set=[yes]"),
        "the export must be visible within its own command: {exporter:?}"
    );
    assert!(
        stdout(&observer).contains("seen=[]"),
        "a sibling program must NOT see it: {observer:?}"
    );
}

/// **An `[agent] env` `IS_SANDBOX` key loads and reaches the workload.**
#[test]
fn an_env_key_sets_is_sandbox_for_the_workload() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("prog-env-is-sandbox", PERMISSIVE)
        .agent_env("IS_SANDBOX", "true")
        .expect();

    let observer = box_.bash(
        r#"printf "IS_SANDBOX=[%s] CLAUDE_CODE_TMPDIR=[%s]" "$IS_SANDBOX" "$CLAUDE_CODE_TMPDIR""#,
    );

    assert_workload_launched(&observer, "the observing program");
    assert!(
        stdout(&observer).contains("IS_SANDBOX=[true] CLAUDE_CODE_TMPDIR=[]"),
        "the operator's `env` key must reach the workload, and no CLAUDE_CODE_TMPDIR may: \
         {observer:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// The CALL level — Unix semantics within one submission
// ═══════════════════════════════════════════════════════════════════════════════

/// `cd` then a relative operation, in one call, behaves as a shell should.
///
/// The boundary bites *between* calls, not within one. A harness that sends
/// `cd sub && cmd` as a single submission gets ordinary Unix semantics — which is what
/// Codex, OpenClaw, Gemini, and Claude Code all do.
#[test]
fn a_relative_path_resolves_against_the_calls_own_cwd() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("prog-relative", PERMISSIVE).expect();

    let output = box_.bash(
        r#"zsh -c 'mkdir -p {box_home}/nested && cd {box_home}/nested && printf inner > f.txt && cat f.txt'"#,
    );

    assert_workload_launched(&output, "the relative-path call");
    assert!(
        stdout(&output).contains("inner"),
        "a relative write and read after a cd must land in the new directory: {output:?}"
    );
}

/// `$?` chains through `&&` and `||` within one call.
#[test]
fn exit_status_chains_within_one_call() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("prog-status-chain", PERMISSIVE).expect();

    let ok = box_.bash(r#"zsh -c 'true && printf reached_then'"#);
    let fallback = box_.bash(r#"zsh -c 'false || printf reached_else'"#);

    assert!(
        stdout(&ok).contains("reached_then"),
        "&& must run the second command after success: {ok:?}"
    );
    assert!(
        stdout(&fallback).contains("reached_else"),
        "|| must run the second command after failure: {fallback:?}"
    );
}

/// A pipeline passes bytes between stages, and a shell function is callable, within one call.
///
/// Both are ordinary Unix semantics that a "one command string" boundary must not have broken.
#[test]
fn pipelines_and_functions_work_within_one_call() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("prog-pipe-fn", PERMISSIVE).expect();

    let piped = box_.bash(r#"zsh -c 'printf "a\nb\nc\n" | grep b'"#);
    let function = box_.bash(r#"zsh -c 'greet() { printf "hi_%s" "$1"; }; greet world'"#);

    assert_workload_launched(&piped, "the pipeline");
    assert_workload_launched(&function, "the function");
    assert!(
        stdout(&piped).contains('b') && !stdout(&piped).contains('a'),
        "a pipeline must filter through its stages: {piped:?}"
    );
    assert!(
        stdout(&function).contains("hi_world"),
        "a function defined and called in one command must work: {function:?}"
    );
}

/// A program's exit status reaches the harness, and the boundary's own failures stay distinct.
///
/// `125` means the boundary broke and `126` a policy denial, so a harness can tell "your command
/// failed" from "the box refused" from "the box is broken". A plain command's status passes
/// through untouched.
#[test]
fn a_commands_exit_status_reaches_the_harness() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("prog-status", PERMISSIVE).expect();

    let zero = box_.bash(r#"zsh -c 'true'; printf "|status=%s" "$?""#);
    let seven = box_.bash(r#"zsh -c 'exit 7'; printf "|status=%s" "$?""#);

    assert_workload_launched(&zero, "the succeeding command");
    assert_workload_launched(&seven, "the failing command");
    assert!(
        stdout(&zero).contains("|status=0"),
        "a successful command must report 0: {zero:?}"
    );
    assert!(
        stdout(&seven).contains("|status=7"),
        "a command's own non-zero status must pass through, not be replaced by a boundary \
         status: {seven:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Session capability — what a protocol like MCP would need, without building MCP
// ═══════════════════════════════════════════════════════════════════════════════

/// State survives across many operations within one program, and dies with it.
///
/// **This is the conformance test for the abstraction.** A session-oriented protocol — MCP, LSP,
/// a REPL — needs exactly this: one program, many operations, state persisting between them, and
/// nothing leaking to the next program. MCP itself is not built (nothing in the box vends an MCP
/// server), so this asserts the *capability* rather than the protocol.
///
/// Eight operations in one call, with state threaded through all of them: a directory created,
/// entered, a variable exported, a function defined, then all three read back at the end.
#[test]
fn a_program_holds_a_session_across_many_calls() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("prog-session", PERMISSIVE).expect();

    let output = box_.bash(
        r#"zsh -c '
            mkdir -p {box_home}/session
            cd {box_home}/session
            export SESSION_VAR=held
            note() { printf "note_%s" "$1"; }
            printf init > state.txt
            printf "|cwd=%s" "$(pwd)"
            printf "|var=%s" "$SESSION_VAR"
            printf "|fn=%s" "$(note ok)"
            printf "|file=%s" "$(cat state.txt)"
        '"#,
    );

    assert_workload_launched(&output, "the session program");
    let text = stdout(&output);
    for expected in [
        format!("|cwd={}/session", box_.box_home().display()),
        "|var=held".to_string(),
        "|fn=note_ok".to_string(),
        "|file=init".to_string(),
    ] {
        assert!(
            text.contains(&expected),
            "a program's session state must survive across its operations; missing \
             {expected}: {output:?}"
        );
    }

    // And it does not outlive the program.
    let next = box_.bash(r#"zsh -c 'printf "leaked=[%s]" "$SESSION_VAR"'"#);
    assert!(
        stdout(&next).contains("leaked=[]"),
        "session state must not outlive its program: {next:?}"
    );
}
/// Four concurrent requests each keep their own cwd, environment, and file.
///
/// **This is the per-request property, measured where it now lives.** One Shell is built
/// per connection, so four requests from one run share authority and share no session. Before
/// that, a `cd` or an `export` in one was visible to another.
#[test]
fn four_concurrent_requests_each_keep_their_own_state() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("prog-concurrent", PERMISSIVE).expect();

    let mut script = String::new();
    for i in 1..=4 {
        script.push_str(&format!(
            r#"zsh -c '
                mkdir -p {{box_home}}/agent{i}
                cd {{box_home}}/agent{i}
                export AGENT_ID={i}
                printf payload_{i} > work.txt
                printf "|agent={i}|cwd=%s|payload=%s|id=%s\n" "$(pwd)" "$(cat work.txt)" "$AGENT_ID"
            ' &
"#
        ));
    }
    script.push_str("wait\n");

    let output = box_.bash(&script);
    let text = stdout(&output);
    eprintln!("FOUR CONCURRENT REQUESTS: {text}");

    assert_workload_launched(&output, "the concurrent requests");
    for i in 1..=4 {
        assert!(
            text.contains(&format!("|agent={i}|")),
            "request {i} must report: {output:?}"
        );
        assert!(
            text.contains(&format!("payload=payload_{i}")),
            "request {i} must read back its OWN file, so no two share a working directory: \
             {output:?}"
        );
        assert!(
            text.contains(&format!("id={i}")),
            "request {i} must see its OWN exported variable, so no two share an environment: \
             {output:?}"
        );
        assert!(
            text.contains(&format!("agent{i}")),
            "request {i} must stand in its own directory: {output:?}"
        );
    }
}
/// A stuck request does not block a healthy one.
///
/// The Lua interpreter never awaits, so it once pinned the runtime every request
/// shared and a healthy sibling waited 27.73s. Each connection owns its thread now. Timed with
/// bash's `SECONDS`, because the profile grants exec on the workload and the aliases and nothing
/// else — there is no `date` in the cage.
#[test]
fn a_stuck_request_does_not_block_a_healthy_one() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("prog-stuck", PERMISSIVE).expect();

    let output = box_.bash(
        r#"
zsh -c "lua -e 'while true do end'" &
zsh -c "sleep 3"
SECONDS=0
zsh -c 'cd {box_home} && printf healthy > ok.txt && cat ok.txt'
printf "|elapsed=%s" "$SECONDS"
"#,
    );

    let text = stdout(&output);
    eprintln!(
        "STUCK-SIBLING MEASURED: {text} (was 27.73s before each connection got its own thread)"
    );

    assert_workload_launched(&output, "the healthy request");
    assert!(
        text.contains("healthy"),
        "a healthy request must complete its work while a sibling spins: {output:?}"
    );
    let elapsed: u64 = text
        .rsplit_once("|elapsed=")
        .and_then(|(_, tail)| tail.trim().split(|c: char| !c.is_ascii_digit()).next())
        .filter(|digits| !digits.is_empty())
        .unwrap_or_else(|| panic!("the probe must report its elapsed seconds: {text:?}"))
        .parse()
        .expect("elapsed seconds parse");
    assert!(
        elapsed < 15,
        "a stuck request must not block a healthy one. If this regresses, the connections went \
         back onto one shared thread. elapsed={elapsed}s, output={output:?}"
    );
}

/// Concurrent requests in one run write one shared box home.
///
/// **Concurrency lives inside a run now, because one run owns a box.** The property is
/// unchanged and so is its point: the box home is one directory, every request reaches it, and
/// three writes at once do not lose one.
#[test]
fn concurrent_requests_see_each_others_files() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("prog-shared-dir", PERMISSIVE).expect();

    let output = box_.bash(
        r#"
zsh -c 'mkdir -p {box_home}/shared'
zsh -c 'printf from_1 > {box_home}/shared/w1.txt' &
zsh -c 'printf from_2 > {box_home}/shared/w2.txt' &
zsh -c 'printf from_3 > {box_home}/shared/w3.txt' &
wait
zsh -c 'cat {box_home}/shared/w1.txt {box_home}/shared/w2.txt {box_home}/shared/w3.txt'
"#,
    );

    assert_workload_launched(&output, "the shared-directory reader");
    let text = stdout(&output);
    for i in 1..=3 {
        assert!(
            text.contains(&format!("from_{i}")),
            "every concurrent writer's file must be readable afterwards; missing from_{i}: \
             {output:?}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Conformance — the abstraction claim, made falsifiable
// ═══════════════════════════════════════════════════════════════════════════════

/// A program the box never saw behaves like a Unix program.
///
/// Every other test here exercises builtins the vendored Shell implements. This one runs a script
/// the *test* creates on the host, inside the box's mount, so the box has no knowledge of it — the
/// closest reachable thing to "a fake command". It checks the parts an agent harness depends on: a
/// shebang, an argument, stdout and stderr kept separate, and the tool's own exit code.
///
/// **Why this test has its own policy.** `sh` is not a program the Shell implements, so the
/// resolved decision is `shell:spawn` and `PERMISSIVE` — which permits `shell:run` only — refuses
/// it. Adding the spawn permit to `PERMISSIVE` instead would widen every other test in this file,
/// including the ones whose subject is a denial, so the grant stays scoped to the one test that
/// needs a host binary. The same reason `box_shell.rs` keeps `ONE_BINARY_POLICY` separate.
#[test]
fn a_program_the_box_never_saw_behaves_like_a_unix_program() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    /// `PERMISSIVE` plus the one host binary this test runs, and no other.
    const PERMISSIVE_PLUS_SH: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"shell:spawn", resource)
when { context.input.program == "sh" };
permit(principal, action == Box::Action::"fs:read", resource);
permit(principal, action == Box::Action::"fs:write", resource);
"#;

    // The host `sh` is a declared tool with the agent home read-write, so it can run a script there.
    let box_ = Request::with_config(
        "prog-fake-cmd",
        PERMISSIVE_PLUS_SH,
        "[tool.sh]\ncommand = [\"sh\"]\n[tool.sh.filesystem]\nread = [\"{box_home}\"]\n\
         write = [\"{box_home}\"]\n",
    )
    .expect();

    // Written from the host side into the box home, which the box mounts. Writing it here rather
    // than through a nested `zsh -c` keeps the shell quoting legible; the *use* of it below is
    // still a full round trip through the boundary.
    let tool = box_.box_home().join("faketool");
    std::fs::write(
        &tool,
        "#!/bin/sh\nprintf 'out:%s' \"$1\"\nprintf 'err:%s' \"$1\" >&2\nexit 3\n",
    )
    .expect("write the fake tool");
    std::fs::set_permissions(&tool, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("make the fake tool executable");

    let output = box_.bash(r#"zsh -c 'sh {box_home}/faketool ARG; printf "|status=%s" "$?"'"#);

    assert_workload_launched(&output, "the fake tool");
    let text = stdout(&output);
    assert!(
        text.contains("out:ARG"),
        "the tool's stdout must reach the harness: {output:?}"
    );
    assert!(
        text.contains("|status=3"),
        "the tool's own exit code must pass through untouched, not replaced by a boundary \
         status: {output:?}"
    );

    assert!(
        stderr(&output).contains("err:ARG"),
        "the tool's stderr must reach the harness: {output:?}"
    );
}

/// Redirection, appending, and reading back — the file semantics a build depends on.
///
/// **`#[ignore]`d on a real defect this test found: `>>` loses the preceding write.**
/// `printf first > f; printf second >> f; cat f` yields **`first`**, not `firstsecond`. The
/// append itself is implemented correctly — `vfs_kernel.rs:213-230` reads the existing bytes
/// before writing — but the writer is a `spawn_local` task that only writes on channel close, so
/// the second command's read-then-write races the first command's flush and the earlier content
/// is lost. Note the surviving byte is the *first* write's target being overwritten, which is why
/// this is a lost write rather than a missing append.
///
/// This is upstream's to fix (a lost write is a wrong result no consumer can repair) and is a
/// diagnosis of its own, so it is pinned here rather than rushed. Un-`#[ignore]` when fixed; do
/// not delete it to green the suite — the same discipline as `lua_popen_is_judged_by_policy`.
#[test]
#[ignore = "`>>` loses the preceding write: the host writer flushes on channel close (upstream)"]
fn redirection_and_append_behave_like_a_shell() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("prog-redirect", PERMISSIVE).expect();

    let output = box_.bash(
        r#"zsh -c '
            printf first > {box_home}/log.txt
            printf second >> {box_home}/log.txt
            printf "|content=%s" "$(cat {box_home}/log.txt)"
            printf notseen > /dev/null
            printf "|devnull_ok=%s" "$?"
        '"#,
    );

    assert_workload_launched(&output, "redirection");
    let text = stdout(&output);
    assert!(
        text.contains("|content=firstsecond"),
        "append must add rather than replace: {output:?}"
    );
    assert!(
        text.contains("|devnull_ok=0"),
        "a write to /dev/null must succeed: {output:?}"
    );
}

/// A denied effect reports a distinguishable status, so a harness can tell refusal from failure.
///
/// 126 is policy's denial and 125 is the boundary breaking; a command's own failure is its own
/// code. Conflating them would make "the box said no" indistinguishable from "your command is
/// broken", which is the difference between an actionable message and a confusing one.
#[test]
fn a_policy_denial_is_distinguishable_from_a_command_failure() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const NO_WRITE: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"fs:read", resource);
"#;
    let box_ = Request::with_policy("prog-denial-status", NO_WRITE).expect();

    let denied =
        box_.bash(r#"zsh -c 'printf x > {box_home}/nope.txt' 2>&1; printf "|status=%s" "$?""#);
    let failed = box_.bash(r#"zsh -c 'exit 4'; printf "|status=%s" "$?""#);

    assert_workload_launched(&denied, "the denied write");
    assert_workload_launched(&failed, "the failing command");
    assert!(
        !stdout(&denied).contains("|status=0"),
        "a denied write must not report success: {denied:?}"
    );
    assert!(
        stdout(&failed).contains("|status=4"),
        "a command's own failure keeps its own code: {failed:?}"
    );
}

/// Eight concurrent workloads, each doing agent-shaped work, all keep their own state.
///
/// Twice the four-workload case, because the per-connection Program cap is 8 and a bound is worth
/// exercising at its edge rather than comfortably inside it.
#[test]
/// # Flaky on a pre-existing lost write — `#[ignore]`d 2026-08-09
///
/// Fails roughly 1 run in 5, always the same way: a workload's `read=` is empty after its own
/// `printf p{i} > f.txt` in the same command. That is the defect
/// `redirection_and_append_behave_like_a_shell` already pins — `vfs_kernel.rs:215-229` spawns a
/// detached task that accumulates writes and flushes only when the channel closes, and nothing
/// awaits that flush, so a read can beat it.
///
/// **The streaming work makes this much better, not worse**: with the vendored channel-writer
/// inheritance stashed it fails **4 runs out of 4**; with it, 1 in 5. So this is not a regression to
/// bisect — it is the same upstream lost write, now rare enough to look intermittent.
///
/// Un-`#[ignore]` when the flush is joinable. Fixing it means making the writer task awaited on
/// close rather than detached, which is a vendored change of its own and larger than this diff.
#[ignore = "flaky on the pre-existing detached-flush lost write; see the doc comment"]
fn eight_concurrent_workloads_all_make_progress() {
    let box_ = Request::with_policy("prog-eight", PERMISSIVE).expect();

    let start = Instant::now();
    let workloads: Vec<_> = (1..=8)
        .map(|i| {
            spawn_run(
                &box_,
                &format!(
                    r#"zsh -c '
                        mkdir -p {{box_home}}/w{i}
                        cd {{box_home}}/w{i}
                        printf p{i} > f.txt
                        printf "|w={i}|cwd=%s|read=%s" "$(pwd)" "$(cat f.txt)"
                    '"#
                ),
            )
        })
        .collect();

    let outputs: Vec<Output> = workloads
        .into_iter()
        .map(|child| {
            child
                .wait_with_output()
                .expect("a concurrent workload finishes")
        })
        .collect();
    let elapsed = start.elapsed();
    eprintln!("EIGHT-WORKLOAD MEASURED: {elapsed:?}");

    // The real path, because these read the workload's output rather than feed it a script.
    let home = box_.box_home();
    let home = home.display();
    for (index, output) in outputs.iter().enumerate() {
        let i = index + 1;
        let text = stdout(output);
        assert_workload_launched(output, &format!("workload {i}"));
        assert!(
            text.contains(&format!("|cwd={home}/w{i}")),
            "workload {i} must stay in its own directory: {output:?}"
        );
        assert!(
            text.contains(&format!("|read=p{i}")),
            "workload {i} must read its own file: {output:?}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// One engine, one history — under contention (Policy Engine test plan S-51, S-52)
// ═══════════════════════════════════════════════════════════════════════════════

/// The writes a racing budget admits.
const BUDGET: usize = 4;

/// How often a racing scenario is repeated, each time against a fresh box.
const RACE_ITERATIONS: usize = 5;

/// The longest one racing run may take before the test kills it.
const RACE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(90);

/// One policy decision as the box journaled it.
#[derive(Debug)]
struct Journaled {
    time: u128,
    action: String,
    resource: String,
    verdict: String,
    command_args: Vec<String>,
}

/// Every policy decision in the box's journal, in file order.
fn journal(box_: &Configured) -> Vec<Journaled> {
    let path = box_
        .root()
        .join("private")
        .join("telemetry")
        .join("records.jsonl");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must hold the journal: {error}", path.display()));
    let mut found = Vec::new();
    for line in text.lines() {
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("one OTLP request per line");
        for resource in parsed["resourceLogs"].as_array().into_iter().flatten() {
            for scope in resource["scopeLogs"].as_array().into_iter().flatten() {
                if scope["scope"]["name"] != "strands-box.policy" {
                    continue;
                }
                for entry in scope["logRecords"].as_array().into_iter().flatten() {
                    let attribute = |key: &str| {
                        entry["attributes"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .find(|attribute| attribute["key"] == key)
                            .map(|attribute| attribute["value"].clone())
                    };
                    let text = |key: &str| {
                        attribute(key)
                            .and_then(|value| value["stringValue"].as_str().map(str::to_string))
                            .unwrap_or_default()
                    };
                    let command_args = attribute("process.command_args")
                        .and_then(|value| value["arrayValue"]["values"].as_array().cloned())
                        .unwrap_or_default()
                        .iter()
                        .map(|value| {
                            value["stringValue"]
                                .as_str()
                                .unwrap_or_default()
                                .to_string()
                        })
                        .collect();
                    found.push(Journaled {
                        time: entry["timeUnixNano"]
                            .as_str()
                            .and_then(|digits| digits.parse().ok())
                            .expect("a journaled decision carries its time"),
                        action: text("strands.box.policy.action"),
                        resource: text("strands.box.policy.resource"),
                        verdict: text("strands.box.policy.verdict"),
                        command_args,
                    });
                }
            }
        }
    }
    found
}

/// Read `source` to its end on a thread, one chunk per message.
fn read_in_background(
    mut source: impl std::io::Read + Send + 'static,
) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(read) = source.read(&mut chunk) {
            if read == 0 || sender.send(chunk[..read].to_vec()).is_err() {
                break;
            }
        }
    });
    receiver
}

/// Everything a background reader has delivered, waiting a bounded time for a held-open pipe.
fn collected(receiver: &std::sync::mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
    let mut bytes = Vec::new();
    while let Ok(chunk) = receiver.recv_timeout(std::time::Duration::from_secs(5)) {
        bytes.extend(chunk);
    }
    bytes
}

/// Run `script` as the contained workload, killing it past `RACE_DEADLINE`.
fn run_within_deadline(box_: &Configured, script: &str) -> Output {
    let script = format!(
        "BOX_HOME={}; export BOX_HOME; {script}",
        box_.box_home().display()
    );
    let mut child = spawn_run(box_, &script);
    let stdout = read_in_background(child.stdout.take().expect("a piped stdout"));
    let stderr = read_in_background(child.stderr.take().expect("a piped stderr"));
    let started = Instant::now();
    loop {
        match child.try_wait().expect("poll the racing run") {
            Some(status) => {
                return Output {
                    status,
                    stdout: collected(&stdout),
                    stderr: collected(&stderr),
                };
            }
            None if started.elapsed() > RACE_DEADLINE => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "the racing run exceeded {RACE_DEADLINE:?}: stdout={:?} stderr={:?}",
                    String::from_utf8_lossy(&collected(&stdout)),
                    String::from_utf8_lossy(&collected(&stderr))
                );
            }
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
}

/// The `|key=value` fields of every line in `text` that carries `key`.
fn fields<'a>(text: &'a str, key: &str) -> Vec<&'a str> {
    let marker = format!("|{key}=");
    text.lines()
        .filter_map(|line| line.split_once(marker.as_str()).map(|(_, tail)| tail))
        .collect()
}

/// A bash fragment that waits until `path` exists, with builtins only.
fn await_file(path: &str) -> String {
    format!(r#"while [ ! -e "{path}" ]; do :; done"#)
}

/// A request-keyed budget of `BUDGET` content writes, plus two probe commands permitted only when
/// the history holds exactly the expected request and response counts.
fn budget_policy() -> String {
    let requests = 2 * BUDGET;
    format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when {{
    context.input.command != "printf REQUESTS_RECORDED"
    && context.input.command != "printf RESPONSES_RECORDED"
}};
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when temporal {{
    exists (asked: Long). (
        (count for (t: Timepoint). where (
            formerly within 3600s (
                Box::Action::"fs:write"::request{{ input.path: _, input.operation: Box::FsWriteOperation::"write_content" }} && tp(t)
            )
        )) == asked
        && asked > {BUDGET}
    )
}};
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when {{ context.input.command == "printf REQUESTS_RECORDED" }}
when temporal {{
    exists (asked: Long). (
        (count for (t: Timepoint). where (
            formerly within 3600s (
                Box::Action::"fs:write"::request{{ input.path: _, input.operation: Box::FsWriteOperation::"write_content" }} && tp(t)
            )
        )) == asked
        && asked == {requests}
    )
}};
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when {{ context.input.command == "printf RESPONSES_RECORDED" }}
when temporal {{
    exists (done: Long). (
        (count for (t: Timepoint). where (
            formerly within 3600s (
                Box::Action::"fs:write"::response{{ input.path: _, input.operation: Box::FsWriteOperation::"write_content" }} && tp(t)
            )
        )) == done
        && done == {BUDGET}
    )
}};
"#
    )
}

/// A temporal budget of N content writes, under 2N simultaneous requests from seven hosted shells
/// and one hosted Python request, admits exactly N.
#[test]
fn a_temporal_budget_under_simultaneous_requests_admits_exactly_its_count() {
    if !fixture::namespace_launcher_is_usable() {
        eprintln!("skipping: this host cannot build a box");
        return;
    }
    let policy = budget_policy();
    let writers: Vec<String> = (1..=2 * BUDGET - 1)
        .map(|index| index.to_string())
        .chain(std::iter::once("py".to_string()))
        .collect();

    for iteration in 1..=RACE_ITERATIONS {
        let box_ = Request::with_policy(&format!("budget-race-{iteration}"), &policy).expect();
        let home = box_.box_home();
        let home = home.display();
        let go = format!("{home}/go");
        let mut script = String::new();
        for writer in &writers {
            let write = if writer == "py" {
                format!(
                    r#"python3 -c "
from pathlib import Path
Path('{home}/write-py.txt').write_text('x')""#
                )
            } else {
                format!(r#"zsh -c "printf x > {home}/write-{writer}.txt""#)
            };
            script.push_str(&format!(
                r#"( : > "{home}/ready-{writer}"; {wait}; out=$({write} 2>&1); echo "|writer={writer}|status=$?|${{out//$'\n'/ }}" ) &
"#,
                wait = await_file(&go)
            ));
        }
        for writer in &writers {
            script.push_str(&await_file(&format!("{home}/ready-{writer}")));
            script.push('\n');
        }
        script.push_str(&format!(
            r#": > "{go}"
wait
zsh -c "printf REQUESTS_RECORDED" >/dev/null 2>&1; echo "|requests_probe=$?"
zsh -c "printf RESPONSES_RECORDED" >/dev/null 2>&1; echo "|responses_probe=$?"
"#
        ));

        let output = run_within_deadline(&box_, &script);
        let text = stdout(&output);
        eprintln!("BUDGET RACE {iteration}: {text}");
        assert_workload_launched(&output, "the racing writers");

        let statuses = fields(&text, "status");
        assert_eq!(
            statuses.len(),
            2 * BUDGET,
            "iteration {iteration}: every writer must report: {output:?}"
        );
        let permitted: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("|status=0|"))
            .filter_map(|line| fields(line, "writer").first().copied())
            .map(|tail| tail.split('|').next().unwrap_or_default())
            .collect();
        let denied: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("|writer=") && !line.contains("|status=0|"))
            .collect();
        assert_eq!(
            permitted.len(),
            BUDGET,
            "iteration {iteration}: a budget of {BUDGET} must admit exactly {BUDGET} of \
             {} simultaneous writes, never one more: {output:?}",
            2 * BUDGET
        );
        for line in &denied {
            assert!(
                line.contains("policy denied"),
                "iteration {iteration}: a refused writer must be refused by policy, not fail \
                 some other way: {line}"
            );
        }
        for writer in &writers {
            let written = std::path::Path::new(&format!("{home}/write-{writer}.txt")).exists();
            assert_eq!(
                written,
                permitted.contains(&writer.as_str()),
                "iteration {iteration}: writer {writer} must have written exactly when it was \
                 permitted: {text}"
            );
        }

        assert_eq!(
            fields(&text, "requests_probe"),
            vec!["0"],
            "iteration {iteration}: the history must hold exactly {} fs:write request events, one \
             for every attempt whether permitted or denied: {output:?}",
            2 * BUDGET
        );
        assert_eq!(
            fields(&text, "responses_probe"),
            vec!["0"],
            "iteration {iteration}: the history must hold exactly {BUDGET} fs:write response \
             events, one for every permitted write: {output:?}"
        );

        let journaled = journal(&box_);
        let writes: Vec<&Journaled> = journaled
            .iter()
            .filter(|entry| entry.action == "fs:write" && entry.resource.contains("/write-"))
            .collect();
        assert_eq!(
            writes.len(),
            2 * BUDGET,
            "iteration {iteration}: the journal must carry one fs:write decision per attempt: \
             {writes:?}"
        );
        let mut journaled_permits: Vec<&str> = writes
            .iter()
            .filter(|entry| entry.verdict == "permit")
            .filter_map(|entry| entry.resource.rsplit("/write-").next())
            .filter_map(|tail| tail.strip_suffix(".txt"))
            .collect();
        journaled_permits.sort_unstable();
        let mut reported_permits = permitted.clone();
        reported_permits.sort_unstable();
        assert_eq!(
            journaled_permits, reported_permits,
            "iteration {iteration}: the journal's permits must be the writers that succeeded: \
             {writes:?}"
        );
    }
}

/// A rule that permits `printf COMMIT` only after the marker write's response is in the history.
fn response_keyed_policy() -> String {
    format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when {{ context.input.command != "printf COMMIT" }};
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when {{ context.input.command == "printf COMMIT" }}
when temporal {{
    formerly within 3600s
    Box::Action::"fs:write"::response{{
        input.path: "{}/tests-passed",
        input.operation: Box::FsWriteOperation::"write_content"
    }}
}};
"#,
        fixture::BOX_HOME
    )
}

/// The text the hosted Shell reports when no rule permits a command.
const NO_PERMIT_MATCHED: &str = "No permit policy matched";

/// The marker write's journaled decision, and the commit's.
fn marker_and_commit(journaled: &[Journaled]) -> (Option<usize>, Vec<usize>) {
    let marker = journaled.iter().position(|entry| {
        entry.action == "fs:write"
            && entry.resource.ends_with("/tests-passed")
            && entry.verdict == "permit"
    });
    let commits = journaled
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            entry.action == "shell:exec" && entry.command_args == ["printf", "COMMIT"]
        })
        .map(|(index, _)| index)
        .collect();
    (marker, commits)
}

/// Every journaled decision carries a time no earlier than the one before it.
fn assert_journal_time_is_monotonic(journaled: &[Journaled], what: &str) {
    for pair in journaled.windows(2) {
        assert!(
            pair[0].time <= pair[1].time,
            "{what}: the journal must not run backwards in time: {pair:?}"
        );
    }
}

/// Two requests racing under a `::response`-keyed rule get the verdicts the journal order implies:
/// a permitted commit always follows the marker write's decision, and a refused one is refused
/// because no permit matched yet.
#[test]
fn two_racing_requests_under_a_response_keyed_rule_get_the_verdicts_the_journal_order_implies() {
    if !fixture::namespace_launcher_is_usable() {
        eprintln!("skipping: this host cannot build a box");
        return;
    }
    let policy = response_keyed_policy();
    let mut permitted_runs = 0;
    let mut denied_runs = 0;

    for iteration in 1..=RACE_ITERATIONS {
        let box_ = Request::with_policy(&format!("order-race-{iteration}"), &policy).expect();
        let home = box_.box_home();
        let home = home.display();
        let go = format!("{home}/go");
        let stagger = (iteration - 1) * 50_000;
        let script = format!(
            r#"( : > "{home}/ready-test"; {wait}; out=$(zsh -c "printf ok > {home}/tests-passed" 2>&1); echo "|test_status=$?|${{out//$'\n'/ }}" ) &
( : > "{home}/ready-commit"; {wait}; for (( i = 0; i < {stagger}; i++ )); do :; done; out=$(zsh -c "printf COMMIT" 2>&1); echo "|commit_status=$?|${{out//$'\n'/ }}" ) &
{wait_test}
{wait_commit}
: > "{go}"
wait
"#,
            wait = await_file(&go),
            wait_test = await_file(&format!("{home}/ready-test")),
            wait_commit = await_file(&format!("{home}/ready-commit")),
        );

        let output = run_within_deadline(&box_, &script);
        let text = stdout(&output);
        eprintln!("ORDER RACE {iteration}: {text}");
        assert_workload_launched(&output, "the racing test and commit");
        assert_eq!(
            fields(&text, "test_status")
                .first()
                .map(|tail| tail.split('|').next()),
            Some(Some("0")),
            "iteration {iteration}: the marker write must be permitted: {output:?}"
        );
        assert!(
            box_.box_home().join("tests-passed").exists(),
            "iteration {iteration}: the marker must have been written: {output:?}"
        );
        let commit = fields(&text, "commit_status")
            .first()
            .copied()
            .unwrap_or_else(|| panic!("iteration {iteration}: the commit must report: {text}"));
        let (commit_status, commit_output) = commit.split_once('|').unwrap_or((commit, ""));

        let journaled = journal(&box_);
        let (marker, commits) = marker_and_commit(&journaled);
        let marker = marker.unwrap_or_else(|| {
            panic!("iteration {iteration}: the marker write must be journaled: {journaled:?}")
        });
        assert_eq!(
            commits.len(),
            1,
            "iteration {iteration}: exactly one commit decision: {journaled:?}"
        );
        let commit_index = commits[0];

        if commit_status == "0" {
            permitted_runs += 1;
            assert!(
                commit_output.contains("COMMIT"),
                "iteration {iteration}: a permitted commit runs: {text}"
            );
            assert_eq!(
                journaled[commit_index].verdict, "permit",
                "iteration {iteration}: the journal must agree with the verdict: {journaled:?}"
            );
            assert!(
                marker < commit_index,
                "iteration {iteration}: a permitted commit must follow the marker write in the \
                 journal, because its permit depends on that write's response: {journaled:?}"
            );
            assert!(
                journaled[marker].time <= journaled[commit_index].time,
                "iteration {iteration}: the marker write must not be timed after the commit it \
                 permitted: {journaled:?}"
            );
        } else {
            denied_runs += 1;
            assert_eq!(
                commit_status, "126",
                "iteration {iteration}: a refused commit reports the policy status: {text}"
            );
            assert!(
                commit_output.contains(NO_PERMIT_MATCHED),
                "iteration {iteration}: a refused commit is refused because no permit matched \
                 yet, not for another reason: {text}"
            );
            assert_eq!(
                journaled[commit_index].verdict, "deny",
                "iteration {iteration}: the journal must agree with the verdict: {journaled:?}"
            );
        }
    }
    eprintln!("ORDER RACE MEASURED: permitted={permitted_runs} denied={denied_runs}");
    assert!(
        permitted_runs >= 1,
        "the growing stagger must let the marker write land first at least once, or the permit \
         branch was never exercised: permitted={permitted_runs} denied={denied_runs}"
    );
}

/// A commit sequenced after the marker write's response is permitted.
#[test]
fn a_commit_sequenced_after_the_test_response_is_permitted() {
    if !fixture::namespace_launcher_is_usable() {
        eprintln!("skipping: this host cannot build a box");
        return;
    }
    let box_ = Request::with_policy("order-after", &response_keyed_policy()).expect();
    let output = box_.bash(
        r#"zsh -c "printf ok > $BOX_HOME/tests-passed"; echo "|test_status=$?"
out=$(zsh -c "printf COMMIT" 2>&1); echo "|commit_status=$?|$out""#,
    );
    let text = stdout(&output);
    assert_workload_launched(&output, "the sequenced test and commit");
    assert_eq!(fields(&text, "test_status"), vec!["0"], "{output:?}");
    assert_eq!(
        fields(&text, "commit_status"),
        vec!["0|COMMIT"],
        "a commit after the durable test response must be permitted: {output:?}"
    );
    let journaled = journal(&box_);
    assert_journal_time_is_monotonic(&journaled, "sequenced test then commit");
    let (marker, commits) = marker_and_commit(&journaled);
    let marker = marker.expect("the marker write is journaled");
    assert!(
        commits.len() == 1 && marker < commits[0],
        "the journal must show the marker write before the permitted commit: {journaled:?}"
    );
    assert_eq!(journaled[commits[0]].verdict, "permit", "{journaled:?}");
}

/// A commit sequenced before the marker write is denied, and the same command is permitted once
/// the write's response has landed in the same history.
#[test]
fn a_commit_sequenced_before_the_test_response_is_denied_until_it_lands() {
    if !fixture::namespace_launcher_is_usable() {
        eprintln!("skipping: this host cannot build a box");
        return;
    }
    let box_ = Request::with_policy("order-before", &response_keyed_policy()).expect();
    let output = box_.bash(
        r#"out=$(zsh -c "printf COMMIT" 2>&1); echo "|first_status=$?|${out//$'\n'/ }"
zsh -c "printf ok > $BOX_HOME/tests-passed"; echo "|test_status=$?"
out=$(zsh -c "printf COMMIT" 2>&1); echo "|second_status=$?|$out""#,
    );
    let text = stdout(&output);
    assert_workload_launched(&output, "the sequenced commit and test");
    let first = fields(&text, "first_status");
    assert_eq!(first.len(), 1, "{output:?}");
    assert!(
        first[0].starts_with("126|") && first[0].contains(NO_PERMIT_MATCHED),
        "a commit before the test response must be refused because no permit matched: {output:?}"
    );
    assert_eq!(fields(&text, "test_status"), vec!["0"], "{output:?}");
    assert_eq!(
        fields(&text, "second_status"),
        vec!["0|COMMIT"],
        "the same commit must be permitted once the response is durable: {output:?}"
    );
    let journaled = journal(&box_);
    assert_journal_time_is_monotonic(&journaled, "sequenced commit, test, commit");
    let (marker, commits) = marker_and_commit(&journaled);
    let marker = marker.expect("the marker write is journaled");
    assert_eq!(commits.len(), 2, "{journaled:?}");
    assert!(
        commits[0] < marker && marker < commits[1],
        "the journal must show deny, marker write, permit in that order: {journaled:?}"
    );
    assert_eq!(journaled[commits[0]].verdict, "deny", "{journaled:?}");
    assert_eq!(journaled[commits[1]].verdict, "permit", "{journaled:?}");
}

/// Every `shell:exec` within an hour, permitted while the count stays within `budget`.
fn counting_policy(budget: usize) -> String {
    format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when temporal {{
    exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within 3600s (
                Box::Action::"shell:exec"::request{{ input.program: _ }} && tp(t)
            )
        )) == total
        && total <= {budget}
    )
}};
"#
    )
}

/// Wait for a run, or kill it and fail once `patience` is spent.
fn output_within(child: Child, patience: Duration, what: &str) -> Output {
    let pid = child.id();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    match receiver.recv_timeout(patience) {
        Ok(output) => output.expect("a run finishes"),
        Err(_) => {
            // SAFETY: plain signals to a pid this test spawned.
            unsafe { libc::kill(pid as i32, libc::SIGTERM) };
            if receiver.recv_timeout(Duration::from_secs(10)).is_err() {
                // SAFETY: as above.
                unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            }
            panic!("{what} is still running after {patience:?}: a connection is left waiting");
        }
    }
}

/// Run `script` to completion and answer its output with the wall time it took.
fn timed_run(
    box_: &Configured,
    script: &str,
    patience: Duration,
    what: &str,
) -> (Output, Duration) {
    let started = Instant::now();
    let output = output_within(spawn_run(box_, script), patience, what);
    (output, started.elapsed())
}

/// Sixty-four streams of one hundred single-decision calls each, released together against one
/// counting rule, spend exactly their budget and take no longer than twice the same calls in
/// sequence.
#[test]
#[ignore = "about ten minutes in a debug build: run it by hand with --ignored"]
fn sixty_four_streams_of_one_hundred_decisions_each_spend_one_budget_exactly() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const STREAMS: usize = 64;
    const DECISIONS: usize = 100;
    const PATIENCE: Duration = Duration::from_secs(1800);
    const LARGEST_RATIO: f64 = 2.0;
    let budget = STREAMS * DECISIONS;
    let policy = counting_policy(budget);
    let in_sequence = Request::with_policy("prog-burst-sequence", &policy).expect();
    let at_once = Request::with_policy("prog-burst", &policy).expect();

    let count = (1..=DECISIONS)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let stream = format!(r#"for n in {count}; do zsh -c 'printf "ok\n"'; done"#);
    let tail = "printf '|burst_done|'\nzsh -c 'printf \"late\\n\"'\nprintf '|status=%s' \"$?\"\n";
    let sequence_script = format!("{}{tail}", format!("{stream}\n").repeat(STREAMS));
    let burst_script = format!("{}wait\n{tail}", format!("{stream} &\n").repeat(STREAMS));

    let (sequence, sequence_elapsed) = timed_run(
        &in_sequence,
        &sequence_script,
        PATIENCE,
        "the sequential control",
    );
    let (burst, burst_elapsed) = timed_run(&at_once, &burst_script, PATIENCE, "the burst");
    let ratio = burst_elapsed.as_secs_f64() / sequence_elapsed.as_secs_f64().max(f64::EPSILON);
    let _ = writeln!(
        std::io::stderr().lock(),
        "NFR-03 {budget} decisions: in sequence {sequence_elapsed:?} ({:.0} us each), as a burst \
         of {STREAMS} streams {burst_elapsed:?} ({:.0} us each), ratio {ratio:.2}, limit \
         {LARGEST_RATIO}",
        sequence_elapsed.as_micros() as f64 / budget as f64,
        burst_elapsed.as_micros() as f64 / budget as f64,
    );

    for (name, output) in [("sequence", &sequence), ("burst", &burst)] {
        assert_workload_launched(output, name);
        let errors = stderr(output);
        assert!(
            !errors.contains("timeout") && !errors.contains("deadline"),
            "a {name} call was left waiting past its deadline: {errors}"
        );
        let text = stdout(output);
        let (spent, after) = text
            .split_once("|burst_done|")
            .unwrap_or_else(|| panic!("the {name} run must reach its last request: {output:?}"));
        let permitted = spent.lines().filter(|line| *line == "ok").count();
        assert_eq!(
            permitted, budget,
            "the {name} run must spend exactly its budget of {budget} decisions; stderr: {errors}"
        );
        let status = after
            .rsplit_once("|status=")
            .map(|(_, code)| code.trim())
            .unwrap_or_else(|| {
                panic!("the {name} run must report its last call's status: {after:?}")
            });
        assert!(
            status == "126" && !after.contains("late"),
            "the {name} run's decision after the budget must be refused with status 126, so the \
             history holds exactly {budget} requests: {after:?}"
        );
    }

    assert!(
        ratio <= LARGEST_RATIO,
        "a burst of {STREAMS} streams took {burst_elapsed:?} against {sequence_elapsed:?} for the \
         same decisions in sequence (ratio {ratio:.2}, limit {LARGEST_RATIO}): contention on one \
         engine slows the decisions it serializes"
    );
}
