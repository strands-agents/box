//! End-to-end Shell routing through the shipped binaries.
//!
//! These assert what the **kernel and the shim actually did**, not what a
//! rendered profile says: each case drives the real `strands-box`, which starts a
//! real shim and contains a real workload. Profile-text assertions belong to
//! `containment`'s conformance suite.
//!
//! The workload here is `/bin/bash`, chosen because it is a native host program
//! that resolves `zsh` off `PATH` exactly as an agent harness does — so these
//! exercise the routing an unmodified Codex would take, without needing Codex.
//! A failure means the Shell boundary moved.
//!
//! Two things deliberately live in the shim's own unit tests rather than here, both
//! because a `bash` workload cannot reach them:
//!
//! - **Abandoning a running command.** `bash` cannot open the shim socket, and the
//!   two ways to fake it from a workload both fail to reproduce anything: killing a
//!   backgrounded alias races its own startup, and synchronising on a marker file is
//!   impossible because the shim's workspace is read-only, so the marker never
//!   appears. An attempt at this test passed against the *unfixed* worker and took
//!   five minutes, which is worse than no test.
//!   `an_abandoned_command_does_not_stop_the_boundary` drives the worker directly.
//! - **Protocol-level malformed input.** Oversized frames, truncated prefixes, and
//!   unknown fields are covered in `shell_protocol`'s tests, which speak the wire
//!   format without needing a client that can.

use std::process::Output;

#[path = "support/fixture.rs"]
mod fixture;

use fixture::{Configured, Request};

/// A policy permitting one exact command, plus reads.
const ONE_COMMAND_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when { context.input.command == "printf SHELL_ROUTED_OK" };
permit(principal, action == Box::Action::"fs:read", resource);
"#;

/// A deliberately permissive policy, used to prove the floors that hold *beneath*
/// policy: a grant policy would allow is still refused by the shim's read-only
/// bind and by containment.
const PERMISSIVE_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"fs:read", resource);
permit(principal, action == Box::Action::"fs:write", resource);
permit(principal, action == Box::Action::"fs:delete", resource);
permit(principal, action == Box::Action::"fs:move", resource);
"#;

/// The exit status the alias reports for a policy denial.
const DENIED_STATUS: i32 = 126;

/// Configure a box under `policy_text` and hand back the running box.
///
/// The policy reaches the box **once**, here. Every `bash` call below carries no
/// authority at all, which is what makes these tests assertions about the rules the
/// box stored rather than about arguments to the command being measured.
fn box_under(policy_text: &str, name: &str) -> Configured {
    Request::with_policy(name, policy_text).expect()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A bash prologue deriving the box's paths from the workload's own `PATH`.
///
/// Derived rather than passed in, for two reasons. The box root contains a name this
/// suite suffixes with its pid, so it is not a constant a test could spell; and
/// deriving is what the *alias* does — each one computes the socket from its own
/// grandparent — so a test that hardcoded the socket would stop checking the
/// relationship the aliases depend on.
///
/// The first `PATH` entry is `<box>/bin`, and the other paths derive from its parent.
const DERIVE_PATHS: &str = r#"
      BIN=${PATH%%:*}
      ROOT=${BIN%/bin}
      ALIAS=$BIN/zsh
      SOCKET=$ROOT/run/box.sock
      PRIVATE=$ROOT/private
"#;

/// How many attempts the kernel refused, counted across both platforms' spellings.
///
/// **The two backends refuse in different words, and counting only one of them reads a refusal
/// as a pass.** Seatbelt denies an operation on a path that exists, so the shell reports
/// `Operation not permitted`. The Linux namespace launcher does not put the path in the
/// workload's mount view at all, so the shell reports `No such file or directory` — which is a
/// *stronger* refusal, because the workload cannot even learn the name.
///
/// Two tests here counted the macOS spelling alone and so failed on Linux for that reason and no
/// other: their outcome assertions — nothing leaked, nothing executed, nothing enumerated — all
/// passed, and only the errno tally did not. Measured 2026-08-12 on the namespace launcher.
///
/// `Permission denied` is included because a Linux mechanism may report `EACCES` where Seatbelt
/// reports `EPERM`, and counting both keeps this tally stable across the two.
///
/// It deliberately does **not** count `Read-only file system` or `Text file busy`. Those come
/// from a bind mount and from an in-use image rather than from a policy decision, so counting
/// them would let a missing grant pass as an enforced one.
fn kernel_refusals(stderr: &str) -> usize {
    [
        "Operation not permitted",
        "No such file or directory",
        "Permission denied",
    ]
    .iter()
    .map(|spelling| stderr.matches(spelling).count())
    .sum()
}

/// The whole point: a command the policy permits is routed to the shim,
/// executed by the Strands Shell, and its output comes back.
#[test]
fn a_permitted_command_routes_through_the_shim() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(ONE_COMMAND_POLICY, "shell-routes");

    let output = box_.bash(r#"zsh -lc "printf SHELL_ROUTED_OK""#);

    assert!(
        stdout(&output).contains("SHELL_ROUTED_OK"),
        "the permitted command must run in the serving shim's Shell: {output:?}"
    );
    assert!(output.status.success(), "{output:?}");
}

/// A temporal rule enforces a cap the request alone could not express.
///
/// This is what Dogwood adds over Cedar: the 21st command is refused because of what
/// already happened, not because of anything in the request. It proves the shim
/// *records* outcomes as well as consulting rules — a `record_outcome` that silently
/// did nothing would leave the count at zero and permit forever.
///
/// The cap is a `forbid`, and that is load-bearing. Written as a second
/// `permit … when temporal { count < N }` it reads equivalently and is a fail-open:
/// permits combine by permit-overrides, so a second permit scoped to the whole action
/// grants every command the narrow rule excluded — a cap that *widens* the policy.
/// The example policy shipped that bug briefly and its own denial check caught it.
#[test]
fn a_temporal_cap_denies_after_its_budget_is_spent() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const CAP: usize = 5;
    let policy = format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when {{ context.input.command == "printf tick" }};
forbid(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when temporal {{
    exists (executed: Long). (
        (count for (t: Timepoint). where (
            formerly within 60s (
                Box::Action::"shell:exec"::response{{ input.command: _ }} && tp(t)
            )
        )) == executed
        && executed >= {CAP}
    )
}};
"#
    );
    let box_ = box_under(&policy, "shell-temporal-cap");

    let attempts = CAP + 3;
    let output = box_.bash(&format!(
        r#"permitted=0
           denied=0
           for (( i = 0; i < {attempts}; i++ )); do
               if zsh -lc "printf tick" >/dev/null 2>&1; then
                   permitted=$(( permitted + 1 ))
               else
                   denied=$(( denied + 1 ))
               fi
           done
           echo "permitted=$permitted denied=$denied""#
    ));

    assert!(
        stdout(&output).contains(&format!("permitted={CAP} denied=3")),
        "the cap must permit exactly {CAP} and then deny: {output:?}"
    );
}

#[test]
fn a_temporal_rule_reads_the_exit_status_of_an_earlier_command() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
@id("gated_after_a_success")
forbid(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when { context.input.command == "printf gated" }
unless temporal {
    formerly within 60s
    Box::Action::"shell:exec"::response{ input.program: _, output.status: 0 }
};
"#,
        "shell-exit-status",
    );

    let output = box_.bash(
        r#"zsh -lc false; echo "false=$?"
           zsh -lc "printf gated"; echo " after-false=$?"
           zsh -lc true; echo "true=$?"
           zsh -lc "printf gated"; echo " after-true=$?""#,
    );

    let stdout = stdout(&output);
    assert!(
        stdout.contains("false=1") && stdout.contains("true=0"),
        "`false` and `true` must run and report their own status: {output:?}"
    );
    assert!(
        stdout.contains(&format!("after-false={DENIED_STATUS}")),
        "a command that exited 1 must not satisfy `output.status: 0`: {output:?}"
    );
    assert!(
        stdout.contains("gated after-true=0"),
        "a command that exited 0 must satisfy `output.status: 0`: {output:?}"
    );
}

/// A command the policy does not name is denied, and the denial is distinguishable.
///
/// 126 rather than the command's own status: a caller must be able to tell "policy
/// refused" from "the command failed", and no output may escape.
#[test]
fn an_unpermitted_command_is_denied_with_no_output() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(ONE_COMMAND_POLICY, "shell-denies");

    let output = box_.bash(r#"zsh -lc "printf SHOULD_BE_DENIED"; echo "status=$?""#);

    assert!(
        !stdout(&output).contains("SHOULD_BE_DENIED"),
        "a denied command must produce no output: {output:?}"
    );
    assert!(
        stdout(&output).contains(&format!("status={DENIED_STATUS}")),
        "a denial must be reported as {DENIED_STATUS}: {output:?}"
    );
    assert!(
        stderr(&output).contains("effect denied"),
        "the denial must say so: {output:?}"
    );
}

/// The alias is discoverable on `PATH`, which is what makes the grant usable.
///
/// A regression guard with history: `AccessMode::Execute` grants no read, and a
/// `PATH` search stats each candidate before exec'ing it. With exec authority
/// alone the alias was executable but invisible, and every harness reported
/// "command not found" — the grant enforced correctly and was never reached. The
/// profile now pairs each exec literal with a metadata read.
#[test]
fn the_alias_is_discoverable_on_path() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(ONE_COMMAND_POLICY, "shell-discoverable");

    let output = box_.bash(&format!(
        r#"{DERIVE_PATHS}
           [[ -e $ALIAS ]] && echo exists
           [[ -x $ALIAS ]] && echo executable
           command -v zsh >/dev/null && echo resolvable"#
    ));

    let seen = stdout(&output);
    for expected in ["exists", "executable", "resolvable"] {
        assert!(
            seen.contains(expected),
            "the alias must be {expected} for a PATH search to find it: {output:?}"
        );
    }
}

/// The alias is never writable, and it is unreadable wherever the backend can say so.
///
/// **Writability is the half that matters, and it holds on every backend.** A workload that could
/// rewrite the alias would replace the program its own exec grant points at — the one program the
/// profile permits. Both a truncate and an append are refused here, whatever the kernel.
///
/// **Unreadability is the half a kernel may be unable to express, and that is a mechanism limit
/// rather than a defect in this crate.** Two facts make it so under the namespace launcher, and
/// the second is the one that closes off every workaround:
///
/// - A bind mount cannot subtract read from its source. The mount view presents the alias by binding
///   it, so read comes with it.
/// - **The workload runs as the same uid as the daemon**, so no file mode separates them. Tightening
///   the alias to `0o100` was tried and reverted: the namespace backend's `elf_dependencies` reads
///   every exec grant to find its interpreter and libraries, as that same uid, and nothing launches
///   — `apply failed: opening '…/bin/zsh' to resolve its dynamic dependencies: Permission denied`.
///   A hard-linked alias shares one inode with the installed image, so the mode change reaches that
///   too.
///
/// No Linux mechanism here expresses it: the namespace launcher builds a mount view, and a bind
/// mount cannot subtract read from a file it makes executable. macOS expresses it through Seatbelt:
/// `process-exec` paired with `file-read-metadata`, never `file-read*`.
///
/// So the read assertion is gated on [`fixture::execute_without_read_is_expressible`] rather than
/// deleted. **It is not `#[ignore]`d and it is not inverted**: on a platform that can express the
/// property this test fails if the property breaks, and on one that cannot it asserts nothing about
/// reads while still proving the writes are refused. The skip is announced, so a green run is not
/// read as a complete one. The severity of what remains is bounded: the workload reads the
/// bytes of a binary it may already execute, and it cannot change them.
#[test]
fn the_alias_image_is_execute_only() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-execute-only");

    // Read from the host, before the workload runs. The operator owns this file; the question is
    // whether the *workload* can change it.
    let alias_before = box_.root().join("bin/zsh");
    let before = std::fs::read(&alias_before).expect("the operator can read its own alias");

    // Bash *builtins* only — `head` and `cat` are not on the workload's PATH, so
    // running them "fails" for every path and would assert nothing. A review found
    // an earlier version of this test doing exactly that: it passed against files
    // that were plainly readable.
    let output = box_.bash(&format!(
        r#"{DERIVE_PATHS}
           # Positive control: a redirect that IS permitted, proving the idiom works.
           printf 'CONTROL\n' > "$BOX_HOME/control.txt"
           read -r control < "$BOX_HOME/control.txt" && echo "control=$control"
           read -r leaked < "$ALIAS" && echo "LEAKED=$leaked"
           printf x >> "$ALIAS"
           printf x > "$ALIAS""#
    ));

    assert!(
        stdout(&output).contains("control=CONTROL"),
        "the positive control must succeed, or the denials below prove nothing: {output:?}"
    );

    // **The property is that the bytes do not change, and that is what is asserted.**
    //
    // Counting error spellings was tried and is fragile in both directions. Three different
    // refusals are correct here — `Operation not permitted` from Seatbelt, `Read-only file system`
    // from a read-only bind, and **`Text file busy` when another box is executing that same
    // inode**, which the alias shares with the installed image whenever the hard link succeeds.
    // Measured: this test passed alone and failed inside its own suite, because a sibling test was
    // running `zsh` at that moment and the append answered `ETXTBSY` instead of `EROFS`.
    //
    // A count is also weak in the other direction: a *writable* alias that happens to be executing
    // is refused too, so a passing count would not prove the grant is right. Comparing the bytes
    // proves it whatever the kernel said, and it does not care what else the suite is doing.
    let alias = box_.root().join("bin/zsh");
    let after = std::fs::read(&alias).expect("the operator can read its own installed alias");
    assert_eq!(
        before, after,
        "the workload must not change the alias: it is the one program its own exec grant points \
         at, so a rewrite would replace what the box permitted. {output:?}"
    );
    assert!(
        !after.is_empty(),
        "an empty alias would make the comparison above vacuous: {output:?}"
    );

    // **Gated on whether the SELECTED BACKEND can express the property — and gating is not inverting.**
    //
    // Where execute-without-read is expressible this asserts it, so a regression there fails. Where it
    // is not, this asserts *nothing about reads* and the write assertions above still stand.
    //
    // Two wrong versions of this gate were written before this one, and each hid the assertion in a
    // different way:
    //
    // 1. An earlier pass gated the assertion and then asserted the leak was **present** where the
    //    property is inexpressible. That is backwards: it pins the gap as desired behaviour, so closing
    //    the gap would fail the test. Skipping says "unknown here"; asserting the leak says "correct
    //    here".
    // 2. The gate then probed the *kernel* for a Landlock ABI and returned `abi > 0`. That was
    //    inverted from what runs, because `containment` selected the namespace launcher only at ABI
    //    **0** and refused containment outright above it, so the assertion was dead on Linux at every
    //    ABI. It now answers about the backend the box runs on, which is the thing the property
    //    belongs to.
    //
    // The gate cannot swallow the assertion everywhere. `execute_without_read_is_expressible` returns
    // `true` unconditionally off Linux, because Seatbelt renders `process-exec` with
    // `file-read-metadata` and never `file-read*` — so on macOS this always runs.
    //
    // What the gap is, so nobody re-diagnoses it: a bind mount cannot subtract read, and the workload
    // runs as the **same uid** as the daemon, so no file mode separates them either. Tightening the
    // alias to `0o100` was tried and reverted — `elf_dependencies` reads every exec grant as that uid
    // and nothing launches. Closing it needs the hard link at `aliases.rs:28` broken into a 20.5 MB
    // per-box copy plus a new field on `containment`'s frozen grant surface. Recorded as an open gap
    // in `box/AGENTS.md`; the maintainers approved the gating.
    if fixture::execute_without_read_is_expressible() {
        assert!(
            !stdout(&output).contains("LEAKED="),
            "the alias's contents must not be readable where the backend can express \
             execute-without-read: {output:?}"
        );
    } else {
        // Announced, so a green run is not mistaken for a complete one. The suite's own convention.
        // It names the backend rather than the platform, because the platform is not the limit: this
        // kernel could express the property and the backend carrying it is gated off.
        eprintln!(
            "skipping: the namespace launcher cannot subtract read from an exec grant, so the \
             alias-read assertion did not run. The write assertions did."
        );
    }
}

/// Every host shell *other than the workload itself* is denied by the kernel, so
/// the alias is the only interpreter the workload can reach.
///
/// This is what makes the routing a boundary rather than a convention: the
/// workload cannot decline to use it.
///
/// `/bin/bash` is deliberately excluded from the list. It is this suite's chosen
/// *workload*, so it holds the workload's own exec grant and re-exec'ing itself is
/// the profile working as specified — one exec literal per grant, and the workload
/// is one of them. An earlier version of this test asserted `/bin/bash` was denied
/// too and failed for exactly that reason: the assertion was wrong, not the
/// boundary. A real Codex workload is not a shell, so its own grant grants no
/// interpreter.
#[test]
fn native_host_shells_other_than_the_workload_are_denied() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-no-native");

    let output = box_.bash(
        r#"for shell in /bin/zsh /bin/sh /bin/dash /usr/bin/env /usr/bin/python3; do
               "$shell" -c "printf NATIVE_RAN_$shell" 2>/dev/null || echo "denied $shell"
           done"#,
    );

    let seen = stdout(&output);
    assert!(
        !seen.contains("NATIVE_RAN"),
        "no host interpreter may execute: {output:?}"
    );
    for shell in [
        "/bin/zsh",
        "/bin/sh",
        "/bin/dash",
        "/usr/bin/env",
        "/usr/bin/python3",
    ] {
        assert!(
            seen.contains(&format!("denied {shell}")),
            "{shell} must be denied: {output:?}"
        );
    }
}

/// The workload cannot start a serving shim of its own.
///
/// The role is chosen by `argv[0]` precisely so this fails: a flag-selected shim
/// would let the workload run one with no policy file and route its own commands
/// through it. The alias is the only name it can reach, and the alias refuses.
#[test]
fn the_workload_cannot_start_its_own_shim() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-no-own-shim");

    let output = box_.bash(
        r#"zsh --serve /tmp/attacker.sock / 2>&1 || echo "shim refused"
           zsh --policy /dev/null -c "printf x" 2>&1 || echo "policy flag refused""#,
    );

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        seen.contains("shim refused") && seen.contains("policy flag refused"),
        "the alias must accept only -c/-lc COMMAND: {output:?}"
    );
    assert!(
        seen.contains("accepts only"),
        "the refusal must name what is accepted: {output:?}"
    );
}

/// The shim's socket may be connected to and nothing else.
///
/// `UnixSocketMode::Connect` rather than `ConnectBind`, and the containing
/// directory carries no write grant — so the workload can neither overwrite the
/// shim's socket nor create one of its own beside it and accept on it.
#[test]
fn the_socket_can_be_reached_but_not_replaced() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-socket-connect");

    let output = box_.bash(&format!(
        r#"{DERIVE_PATHS}
           ( printf x > "$SOCKET" ) 2>/dev/null || echo "socket not writable"
           ( printf x > "$ROOT/run/attacker.sock" ) 2>/dev/null || echo "run not writable"
           zsh -lc "printf STILL_ROUTED""#
    ));

    let seen = stdout(&output);
    assert!(
        seen.contains("socket not writable") && seen.contains("run not writable"),
        "the socket and its directory must not be writable: {output:?}"
    );
    assert!(
        seen.contains("STILL_ROUTED"),
        "the route must survive the attempts: {output:?}"
    );
}

/// The box's private tree is unreachable: neither the shim's policy nor the
/// shim image can be read or named.
///
/// The policy matters because a workload that could rewrite it would choose the
/// rules judging its own commands. The image matters because its filename is what
/// selects serve mode.
#[test]
fn the_shims_policy_and_image_are_unreachable() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-private-tree");

    // Builtins and the kernel's own refusal, for the same reason as above. The
    // earlier version of this test also probed `$PRIVATE/strands-box-sock-alias`, which
    // never exists — the shim runs from the *installed* image and only the alias is
    // materialized — so those assertions passed against a nonexistent path. The
    // installed image is what must be unreachable, so that is what is probed.
    let output = box_.bash(&format!(
        r#"{DERIVE_PATHS}
           read -r leaked < "$PRIVATE/policy.dw" && echo "POLICY_LEAKED=$leaked"
           printf x > "$PRIVATE/policy.dw"
           # The private directory itself must not be listable either: enumerating it
           # would disclose the shim's filenames even without reading them.
           for entry in "$PRIVATE"/*; do echo "ENUMERATED=$entry"; done"#
    ));

    assert!(
        !stdout(&output).contains("POLICY_LEAKED="),
        "the shim's policy must not be readable — a workload that could read it \
         learns exactly which commands to submit, and one that could write it would \
         choose the rules judging itself: {output:?}"
    );
    // An unmatched glob expands to itself, so a real listing is the only way a
    // concrete name appears. Probed against the names that are *actually* children of
    // `private/` — the stored authority, the box record, and the daemon's liveness. An
    // earlier version probed `strands-box-contain-trampoline`, which the content-addressed trampoline
    // cache means is no longer a filename anywhere: the assertion held against nothing.
    let seen = stdout(&output);
    for name in ["policy.dw", "box.toml", "live.json"] {
        assert!(
            !seen.contains(&format!("ENUMERATED={name}")) && !seen.contains(&format!("/{name}")),
            "the private directory must not be enumerable, and {name} is in it: {output:?}"
        );
    }
    // Reading the policy and writing it: two kernel refusals, in whichever words this
    // platform's backend uses. See `kernel_refusals` — on Linux both are `ENOENT`, because the
    // private tree is not in the workload's mount view at all.
    assert_eq!(
        kernel_refusals(&stderr(&output)),
        2,
        "reading and writing the shim's policy must both be denied by the kernel: \
         {output:?}"
    );
}

/// The installed shim image cannot be executed by the workload.
///
/// The role dispatch (`argv[0]`) is only half the reason a workload cannot start its
/// own shim — the other half is that it cannot reach the image under *any* name.
/// A review found that renaming the image via symlink defeats the argv check, so this
/// pins the containment half, which is what actually holds.
#[test]
fn the_installed_shim_image_cannot_be_executed() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-image-unreachable");
    let installed = fixture::box_binary()
        .parent()
        .expect("the box binary has a directory")
        .join("strands-box-sock-alias");

    let output = box_.bash(&format!(
        r#"read -r leaked < "{image}" && echo "IMAGE_LEAKED=$leaked"
           "{image}" --serve /tmp/attacker.sock / && echo "IMAGE_EXECUTED""#,
        image = installed.display()
    ));

    let seen = stdout(&output);
    assert!(
        !seen.contains("IMAGE_LEAKED=") && !seen.contains("IMAGE_EXECUTED"),
        "the installed image must be neither readable nor executable: {output:?}"
    );
    assert_eq!(
        kernel_refusals(&stderr(&output)),
        2,
        "reading and executing the installed image must both be denied: {output:?}"
    );
    assert!(
        !std::path::Path::new("/tmp/attacker.sock").exists(),
        "no attacker-controlled shim socket may be created"
    );
}

/// The mount's *scope* is the floor policy cannot widen — not its writability.
///
/// **Replaces `the_shims_home_mount_is_read_only_beneath_policy`, which asserted the
/// opposite and was correct until 2026-08-07.** The bind was `bind_direct_readonly`, so a
/// write was refused by the mount before policy was consulted. Measured, that cost parity
/// and protected nothing: under one identical `permit fs:write`, Monty wrote to the box home
/// and succeeded while the Shell was refused — one rule, two boundaries, two meanings — and
/// the home was writable anyway through the workload's own blanket `file-write*` grant and
/// through Monty. A Shell "write" also still *succeeded* into its own VFS, invisible to
/// everyone, which is a worse failure than a denial. `box_cardinality.rs` E10a/E10b pin the
/// new behaviour: policy decides a write, and withholding `fs:write` denies both boundaries.
///
/// What survives, and is what this test now pins: **the deny floor**, not the mount scope.
///
/// The workload cannot reach the operator's home directly. The policy-controlled Shell can, so a
/// permissive policy lets it read an operator file. The first assertion measures that distinction.
///
/// What protects the operator instead is that absent policy denies and the starter policy scopes
/// `fs:read` to the workspace. A `permit` on everything is an operator choosing to grant everything.
///
/// What a `permit` still cannot reach is any box's private tree or trusted Box state. That is
/// `Reach`'s deny floor, and it is what this test pins.
#[test]
fn the_mount_scope_is_a_floor_policy_cannot_widen() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-scope-floor");

    // Planted in the operator's home. Only the policy-controlled interpreter can reach it.
    let secret = box_.operator_home().join("operator-only.txt");
    std::fs::write(&secret, "OPERATOR_SECRET").expect("plant an operator-owned file");

    let reachable = box_.bash(&format!(r#"zsh -lc "cat {}" 2>&1"#, secret.display()));
    assert!(
        format!("{}{}", stdout(&reachable), stderr(&reachable)).contains("OPERATOR_SECRET"),
        "a permissive policy lets the interpreter reach the operator home: \
         {reachable:?}"
    );

    // And the floor: this box's own stored policy is refused, whatever policy says.
    let stored = box_.root().join("private/policy.dw");
    let output = box_.bash(&format!(
        r#"zsh -lc "cat {}" 2>&1
           zsh -lc "printf pwned > {}" 2>&1"#,
        stored.display(),
        stored.display()
    ));

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        !seen.contains("permit("),
        "no policy may reach the box's own stored rules: {output:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&secret).unwrap_or_default(),
        "OPERATOR_SECRET",
        "and must not overwrite it either: {output:?}"
    );

    // The paired positive: inside the home, a permitted write now *does* land, which is
    // what makes `fs:write` mean the same thing here as at the Monty boundary.
    let home = box_.box_home();
    let inside = box_.bash(&format!(
        r#"zsh -lc "printf allowed > {}/written-by-shell""#,
        home.display()
    ));
    assert_eq!(
        std::fs::read_to_string(home.join("written-by-shell")).unwrap_or_default(),
        "allowed",
        "a permitted write inside the mount must reach the host: {inside:?}"
    );
}

/// The Shell reaches the workload's files under the **same** spelling the workload used.
///
/// This is the inversion of a cost this suite used to pin. A fixed `/home/strands-box` mount
/// gave one directory two names: the workload wrote through its own `$HOME`, the Shell read the
/// same bytes at the mount, and the workload's own spelling did **not** resolve in a Shell
/// command. The old test asserted that, and its own note said it was the test to change if the
/// decision was revisited.
///
/// It was revisited. The home is now named by its host path in both places, so `$HOME` is one
/// string for the workload, the Shell, and Monty.
///
/// **The portability problem the fixed mount solved is now unsolved**, and that is worth stating
/// rather than implying. `[[bind]]` used to carry it — a bind kept its mount point, so a policy
/// checked into a repository named `/workspace` on every clone — and the shared operator home
/// removed binds. A path in an authored policy is a host path, so it holds only on the machine that
/// wrote it. `box/AGENTS.md` records this.
#[test]
fn the_shell_reaches_workload_files_under_the_workloads_own_spelling() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-one-spelling");
    let workspace = box_.workspace().display().to_string();

    // `bash` expands `$BOX_HOME` before the alias sees it, so the Shell is handed the same
    // absolute host path the workload just wrote through.
    let output = box_.bash(
        r#"printf parity > "$BOX_HOME/written-by-workload"
           zsh -lc "cat $BOX_HOME/written-by-workload"
           zsh -lc "pwd""#,
    );

    let seen = stdout(&output);
    assert!(
        seen.contains("parity"),
        "the Shell must read the workload's file at the workload's own spelling: {output:?}"
    );
    // The Shell's cwd is the **workspace**, not the box home. It was the box home until 2026-08-18,
    // which made every relative path resolve outside the rules an operator writes.
    // `the_shells_home_matches_the_workloads_and_its_cwd_is_the_project` is what pins the pair;
    // this asserts it too, so a change that moved it back fails here rather than only there.
    assert!(
        seen.contains(&workspace),
        "the Shell's cwd is the workspace's host path: {output:?}"
    );
}

/// Every conventional shell name is on the workload's PATH, and each reaches the
/// shim.
///
/// This is the point of materializing a set rather than one name: a harness resolves its
/// shell by name and each picks its own — Codex emits `zsh -lc`, the Strands harness
/// `sh -c`, others `bash -c`. The set is the three observed spellings; a harness asking
/// for anything else is refused, which is fail-closed rather than broken-open.
///
/// Detected, not configured: an operator should not need to know which shell their
/// agent's tool loop happens to spell. Each name is a separate exec literal in the
/// profile — a repeated rule, so N names authorize exactly N paths.
#[test]
fn every_conventional_shell_name_routes_through_the_shim() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-alias-set");

    // `command -v` resolves off the composed PATH without executing; then each name
    // runs a command, which must reach the one shim.
    let output = box_.bash(
        r#"for s in zsh bash sh; do
             command -v "$s" >/dev/null || { echo "MISSING=$s"; continue; }
             "$s" -c "printf 'ROUTED=%s\n' $s"
           done"#,
    );

    let seen = stdout(&output);
    assert!(
        !seen.contains("MISSING="),
        "every conventional shell name must be on the workload's PATH: {output:?}"
    );
    for shell in ["zsh", "bash", "sh"] {
        assert!(
            seen.contains(&format!("ROUTED={shell}")),
            "{shell} must route through the shim: {output:?}"
        );
    }
}

/// A script file routes through the shim, and policy judges it by its **text**.
///
/// The other spelling a harness emits. An agent's shell tool sends `-c` for a short
/// command and writes a temp script when the command grows — and before 2026-08-07 the
/// script form hit the alias's usage error, so a tool that switched spellings mid-session
/// reported the box had no shell at all.
///
/// The policy here permits one exact command string and nothing else, which is what makes
/// this an assertion about text rather than about plumbing: the script runs only if the
/// shim received its *contents*. Had the alias forwarded the path, the policy would have
/// had to name a filename — and a rule matching a temp-file path authorizes whatever that
/// file happens to contain.
#[test]
fn a_script_file_routes_through_the_shim_and_is_judged_by_its_text() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(ONE_COMMAND_POLICY, "shell-script-file");

    // The permitted command is `printf SHELL_ROUTED_OK`, written to a file rather than
    // passed as an argument. The second script holds a command the policy does not name,
    // so the denial proves the text — not the fact of being a script — is what is judged.
    let output = box_.bash(
        r#"printf 'printf SHELL_ROUTED_OK' > "$BOX_HOME/permitted.sh"
           printf 'printf SHOULD_BE_DENIED' > "$BOX_HOME/denied.sh"
           zsh "$BOX_HOME/permitted.sh"; echo "permitted_status=$?"
           zsh "$BOX_HOME/denied.sh"; echo "denied_status=$?""#,
    );

    let seen = stdout(&output);
    assert!(
        seen.contains("SHELL_ROUTED_OK") && seen.contains("permitted_status=0"),
        "a script whose text the policy permits must run: {output:?}"
    );
    assert!(
        !seen.contains("SHOULD_BE_DENIED"),
        "a script whose text the policy does not name must produce no output: {output:?}"
    );
    assert!(
        seen.contains(&format!("denied_status={DENIED_STATUS}")),
        "the denial must be reported as {DENIED_STATUS}, exactly as for -c: {output:?}"
    );
}

/// A script the workload cannot read fails in the workload, not in the shim.
///
/// The alias reads the script itself, so the read happens under the *workload's*
/// containment. That is the reason the design reads rather than forwards a path: the
/// shim's own view is a read-only bind of a different tree, so a path it opened would be
/// resolved against grants the workload never held. Probed against the box's private
/// tree, which is exactly a file the shim could reach and the workload may not.
#[test]
fn a_script_the_workload_cannot_read_is_refused_in_the_workload() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-script-unreadable");

    let output = box_.bash(&format!(
        r#"{DERIVE_PATHS}
           zsh "$PRIVATE/policy.dw" 2>&1; echo "status=$?""#
    ));

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        !seen.contains("permit(") && !seen.contains("forbid("),
        "the stored policy must not be executed as a script — nor echoed back in the \
         error, which would disclose it: {output:?}"
    );
    assert!(
        seen.contains("read Shell script"),
        "the refusal must come from the alias's own read, under the workload's \
         containment: {output:?}"
    );
}

/// The shim's own image name is never materialized as an alias.
///
/// One image picks its role by filename, so an alias wearing `strands-box-sock-alias`
/// would reach serve mode — where it takes a socket path and a policy file as
/// arguments the workload would then control. The alias names are a fixed list in
/// `layout.rs` rather than an input, which is what makes that impossible; this asserts
/// the kernel agrees.
#[test]
fn the_shim_image_name_is_not_on_the_workloads_path() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-no-shim-alias");

    let output = box_.bash(
        r#"command -v strands-box-sock-alias && echo "BROKER_REACHABLE" || echo "shim absent""#,
    );

    let seen = stdout(&output);
    assert!(
        !seen.contains("BROKER_REACHABLE") && seen.contains("shim absent"),
        "the shim image must not be reachable by name: {output:?}"
    );
}

/// The hosted Shell's only outbound path is the box's own egress gateway.
///
/// The Shell runs *outside* the box's containment, so a direct dial would be an egress route
/// around the only governed one the box has. Its one route is the gateway, which
/// judges a Shell `curl` under the same `net:*` policy as workload traffic. `PERMISSIVE_POLICY`
/// grants no `net:*`, so the gateway refuses the CONNECT before any network is touched: the
/// routed request fails at send with exit **6** and no origin body.
///
/// The exit code pins the gateway as the cause and rules out the vacuous alternatives. Exit 6 is
/// the transport-error code, reached only after `curl` ran and the routed request left for the
/// proxy. A missing builtin exits 127, a denied exec 126, and the two `PermissionDenied` floors —
/// the Shell's own SSRF floor and a disabled network — exit 1 with `access denied` or `network
/// access disabled`. `-sS` keeps the error visible; `-s` alone hides it. A live positive control
/// would need a public host, because the SSRF floor blocks the loopback a local upstream binds,
/// and this suite otherwise reaches no external network.
#[test]
fn the_shims_shell_has_no_network_path() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-no-egress");

    let output = box_.bash(r#"zsh -lc "curl -sS https://example.com"; echo "status=$?""#);

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    // Three platform-agnostic assertions cover "no network path": `curl`
    // exits non-zero, the failure is the gateway's own CONNECT refusal
    // (NOT the shell kernel's `disable_network` fallback or the SSRF
    // floor), and nothing that looks like a response body comes back.
    // Linux (namespace launcher) exits 6 through the gateway; macOS
    // (Seatbelt) exits with a different code through the same gateway;
    // both satisfy the bound. Naming the exact Linux exit as the
    // positive check made the assertion Linux-only, while the security
    // property held on both platforms.
    assert!(
        seen.contains("status=") && !seen.contains("status=0"),
        "the routed curl must fail at the egress boundary — refused by the box's gateway, \
         not by the shell kernel's `disable_network` fallback, and not by a missing curl. \
         Linux exits with the transport-error 6; macOS (Seatbelt) exits with a different \
         code, and both satisfy this bound. A `status=0` would mean egress escaped, a \
         missing `status=` would mean the shim did not run curl at all: {output:?}"
    );
    assert!(
        !seen.contains("network access disabled")
            && !seen.contains("access denied")
            && !seen.contains("command not found"),
        "the failure must be the gateway's CONNECT refusal, not a disabled network, the SSRF \
         floor, or a missing curl: {output:?}"
    );
    assert!(
        !seen.contains("<html") && !seen.contains("<!doctype") && !seen.contains("Example Domain"),
        "no origin body may come back: {output:?}"
    );
}

/// Shell state does NOT persist across requests: one request, one Shell.
///
/// **This asserted the opposite until 2026-08-08**, with the rationale that
/// persistence "is what makes a multi-step agent session coherent." That rationale did not
/// survive contact with the harnesses: coherence comes from the harness passing a working
/// directory per call — Codex makes `workdir` **required** on every `shell` call — not from
/// the box remembering one.
///
/// What persistence actually bought was a cross-run channel. The daemon holds one Shell for
/// the whole box, so an `export` or a `cd` here was visible to a *different*
/// `strands-box run` (`box_cardinality.rs` E1b/E1c). Two runs share authority by design;
/// they were never meant to share a mutable session.
///
/// The `-lc` spelling is kept deliberately: it is what an agent's shell tool emits, so this
/// asserts the no-carry property on the path a real harness takes.
#[test]
fn shell_state_does_not_persist_across_requests() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-per-request");

    let output = box_.bash(
        r#"zsh -lc "export CARRIED=kept"
           zsh -lc 'printf "carried=[%s]" "$CARRIED"'"#,
    );

    assert!(
        stdout(&output).contains("carried=[]"),
        "each request must get its own Shell, so nothing carries: {output:?}"
    );
}

/// **`$HOME` is one string for the workload and the Shell. `$PWD` is the PROJECT.**
///
/// Two separate properties, and each has broken once.
///
/// `HOME` is the *same* string on both sides. The Shell once fabricated its own mount while `HOME`
/// kept the vendored default of `/home/lash`, so `~` expanded outside the mount and a bare `cd`
/// walked away from it. Then the composed workload environment moved `HOME` to the operator's home
/// while this side still reported the box home — the same defect with the sides swapped. So the
/// assertion is a *comparison* rather than a literal: whatever `HOME` is, both sides read one
/// string. A literal is what let the second break look like a passing test.
///
/// `PWD` is the workspace on both sides, because the operator's policy names the workspace — a
/// relative `cat src/main.rs` resolved against the home instead, fell outside every rule, and was
/// default-denied. Measured: it broke the shipped codex example's own permitted-read check. `HOME`
/// is what `[agent] env` declares, which this fixture sets to a directory of its own under the
/// operator home; two directories, each with one name.
#[test]
fn the_shells_home_matches_the_workloads_and_its_cwd_is_the_project() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    // Scoped to the workspace, which is what an operator's policy names. `fs:write` too, so the
    // relative-path check below can create the file it then reads.
    const PROJECT_SCOPED_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.path like "{workspace}*" };
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when { context.input.path like "{workspace}*" };
"#;
    let box_ = box_under(PROJECT_SCOPED_POLICY, "shell-home-identity");
    let box_home = box_.box_home().display().to_string();
    let workspace = box_.workspace().display().to_string();
    let operator_home = box_.operator_home().display().to_string();

    // The single quotes keep each variable unexpanded by the workload's bash, so the Shell is the
    // one that resolves it. The double-quoted line is the workload answering for itself.
    let output = box_.bash(
        r#"printf "WORKLOAD_HOME=%s
" "$HOME"
           printf "WORKLOAD_PWD=%s
" "$PWD"
           zsh -lc 'printf "SHELL_HOME=%s
" "$HOME"'
           zsh -lc 'printf "SHELL_PWD=%s
" "$PWD"'
           zsh -lc 'printf "USER=%s
" "$USER"'
           zsh -lc 'printf relative > ./from-a-relative-path && cat ./from-a-relative-path'"#,
    );

    let seen = stdout(&output);
    let value_of = |name: &str| -> String {
        seen.lines()
            .find_map(|line| line.trim().strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no {name} in the Shell's environment: {output:?}"))
            .to_string()
    };

    // **One directory, one name.** Either side changing alone fails here.
    assert_eq!(
        value_of("SHELL_HOME"),
        value_of("WORKLOAD_HOME"),
        "the agent reads $HOME with its own syscalls and through the alias, and a disagreement          means a path it writes it cannot find. Output: {output:?}"
    );
    assert_eq!(
        value_of("SHELL_HOME"),
        box_home,
        "$HOME must be the home `[agent] env` declares, which this fixture sets under the \
         operator home. Output: {output:?}"
    );
    assert_ne!(
        value_of("SHELL_HOME"),
        operator_home,
        "this fixture declares a home of its own, and asserting the inequality is what keeps the \
         line above from passing on a host where the two happen to coincide: {output:?}"
    );

    // **One directory, and both sides name it: the workspace.**
    //
    // This asserted an *inequality* until 2026-08-19, because the workload could not enter a
    // directory its profile did not grant and granting the workspace `Read` would have let its own
    // syscalls read it. `AccessMode::Traverse` states the third thing that was missing — present,
    // holding nothing — so the two collapsed into one answer on purpose.
    assert_eq!(
        value_of("SHELL_PWD"),
        workspace,
        "the interpreters must start in the workspace, or a relative path falls outside the rules \
         the operator wrote: {output:?}"
    );
    assert_eq!(
        value_of("WORKLOAD_PWD"),
        workspace,
        "the workload starts in the workspace too, so a relative path means the same file whichever \
         side resolves it: {output:?}"
    );
    assert_eq!(
        value_of("SHELL_PWD"),
        value_of("WORKLOAD_PWD"),
        "both sides must name one directory; a disagreement is the defect of one directory with \
         two names: {output:?}"
    );
    // **And the workspace is NOT the home**, which is what keeps the equality above from being
    // satisfied by collapsing everything into the home. `HOME` and `PWD` answer different
    // questions, and this is what says so.
    assert_ne!(
        value_of("WORKLOAD_PWD"),
        box_home,
        "the working directory is the workspace, not the home; if these are equal the workspace \
         grant did not take effect: {output:?}"
    );
    assert!(seen.contains("USER=strands-box"), "{output:?}");

    // **The property all of this exists for.** A relative path through the alias reaches the
    // workspace, so the workspace-scoped rule covers it. This is what was default-denied before.
    assert!(
        seen.contains("relative"),
        "a relative write and read through the alias must land in the workspace and be permitted          by the workspace-scoped rule: {output:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// One authority across both boundaries (docs/design/decisions.md#one-policy-engine-per-box)
// ═══════════════════════════════════════════════════════════════════════════════

/// A rule spanning the Shell and the network.
///
/// `unless temporal { formerly … }` is the exfiltration shape: egress is open until the
/// marked file is read through the Shell, and closed afterwards. The predicate matches
/// an `fs:read` **resolution**, so only an effect that actually happened can fire it — a
/// denied attempt cannot (`policy/CLAUDE.md`, "Known Limits").
///
/// The clause gates **`net:connect`**, deliberately. The proxy answers a connect denial
/// at CONNECT with `403` before any TLS (`tests/support/egress_probe.rs`), so the verdict
/// is directly observable. Gating `http:request` instead would put the assertion behind a
/// handshake the box refuses anyway — it will not trust a fixture CA — and the test could
/// not tell a policy denial from that refusal.
fn no_egress_after_secret_read(host: &str, port: u16) -> String {
    format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);

permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource);

permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource)
when {{ context.input.host == "{host}" && context.input.port == {port} }}
unless temporal {{
    formerly within 300s
    Box::Action::"fs:read"::response{{
        input.path: "{{box_home}}/secret",
        input.operation: Box::FsReadOperation::"read_content"
    }}
}};
"#
    )
}

/// Run the egress probe as the contained workload, against `authority`.
///
/// The probe insists on a bearer-token variable before it will dial, so it is pointed at
/// `HOME` — a variable the box always composes. No credential is provisioned because none
/// is needed: what is measured is the *connect verdict*, which the proxy renders before
/// any token is read. Naming an absent variable would make the probe exit before reaching
/// the boundary, which is how an earlier version of this test passed vacuously.
fn probe_egress(box_: &Configured, authority: &str) -> Output {
    box_.run(&[
        env!("CARGO_BIN_EXE_box-egress-probe"),
        &format!("https://{authority}/v1/upload"),
        "HOME",
    ])
}

/// Probe egress, read through an interpreter alias, then probe again — all in ONE run.
///
/// **One run fixes the event order.** The `fs:read` and later `net:connect` meet in the same
/// box history. The probe reaches both boundaries itself, then prints `status=`, `read=`, and
/// `status_after=`.
fn probe_egress_around_read(box_: &Configured, authority: &str, read: &[&str]) -> Output {
    let url = format!("https://{authority}/v1/upload");
    let mut argv = vec![
        env!("CARGO_BIN_EXE_box-egress-probe"),
        url.as_str(),
        "HOME",
        "--",
    ];
    argv.extend_from_slice(read);
    box_.run(&argv)
}

/// Reading a secret through the Shell alias closes the box's egress — the acceptance test for one `Policy` per box.
///
/// **Both boundaries are reached by one run** so the probe fixes their order. It reads the secret
/// itself between its two requests. Port 9 is deliberate: the refusal must come from the boundary,
/// not from a listener.
#[test]
fn reading_a_secret_through_the_alias_closes_egress() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let (host, port) = ("localhost", 9);
    let authority = format!("{host}:{port}");
    let box_ = box_under(&no_egress_after_secret_read(host, port), "one-policy-cross");

    // Planted in a first run: only the READ has to share a history with the egress decision.
    let plant = box_.bash(r#"printf 'super-secret' > "$BOX_HOME/secret""#);
    assert!(
        plant.status.success(),
        "the secret must be planted: {plant:?}"
    );

    let secret = box_.box_home().join("secret");
    let read = format!("cat {} > /dev/null", secret.display());
    let output = probe_egress_around_read(&box_, &authority, &["zsh", "-lc", &read]);
    let seen = format!("{}{}", stdout(&output), stderr(&output));
    eprintln!("CROSS-BOUNDARY (shell): {seen}");

    assert!(
        seen.contains("read=ok"),
        "the read must succeed, or the predicate never had a chance to fire: {output:?}"
    );
    assert!(
        !seen.contains("status=403"),
        "egress must be permitted before the read, or the rule below proves nothing: {output:?}"
    );
    assert!(
        seen.contains("status_after=403"),
        "egress must close once the secret is read; two histories leave it open: {output:?}"
    );
}

/// The control that makes the test above mean something.
///
/// Same policy, same box, same call shape — but the Shell reads a *different* path, so
/// the predicate does not match and egress stays open. Without this, a denial above could
/// be caused by any Shell activity rather than by reading that file.
#[test]
fn reading_an_unrelated_file_leaves_egress_open() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let (host, port) = ("localhost", 9);
    let authority = format!("{host}:{port}");
    let box_ = box_under(
        &no_egress_after_secret_read(host, port),
        "one-policy-control",
    );

    let read = box_.bash(&format!(
        r#"printf 'harmless' > "$BOX_HOME/notes"
           zsh -lc 'cat {}/notes > /dev/null && printf "READ_OK\n"'"#,
        box_.box_home().display()
    ));
    assert!(
        stdout(&read).contains("READ_OK"),
        "the unrelated read must succeed: {read:?}"
    );

    let after = probe_egress(&box_, &authority);
    let after_seen = format!("{}{}", stdout(&after), stderr(&after));
    assert!(
        !after_seen.contains("status=403"),
        "an unrelated read must not close egress: {after:?}"
    );
}

/// The vendored Lua interpreter is reachable, and its effects are mediated.
///
/// Recorded because it is the sharpest fact about what hosting the Shell puts in the
/// daemon. `mlua` is a **non-optional** dependency of the vendored Shell
/// with `features = ["lua54", "async", "vendored"]`, so a Lua 5.4 **C** interpreter —
/// roughly 500 `unsafe` FFI blocks in the binding alone — is compiled into whichever
/// process hosts the Shell, and `builtins/mod.rs` exposes it as a `lua` builtin that
/// executes workload-supplied source. Measured 2026-08-07: `lua -e "print(1+1)"`
/// answers `2` from inside a box.
///
/// So "the Shell is a small reviewed parser" is false, and any threat model that rests
/// on it is wrong. What actually holds is *mediation*: Lua's filesystem and process
/// reach is serviced through the Shell's kernel, so `io.open` on a host path is refused
/// and `io.popen` sees the Shell's synthesized environment. The companion assertion is
/// `box_credentials.rs::the_shell_cannot_read_the_daemons_resolved_secrets`, which
/// probes the same interpreter against the daemon's real secret.
///
/// If Lua ever becomes optional, gate it off for the box: an interpreter the box never
/// exposes is strictly better than one it exposes and mediates.
#[test]
fn the_lua_interpreter_is_reachable_and_mediated() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-lua-mediated");

    let output = box_.bash(
        r#"zsh -lc 'lua -e "print(1+1)"'
           zsh -lc 'lua -e "print(io.open([[/etc/passwd]]))"'"#,
    );

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        seen.contains('2'),
        "the Lua builtin is reachable from inside a box; if this changed, update the threat \
         model in docs/design/decisions.md#the-interpreters-run-in-the-trusted-process rather \
         than deleting the test: {output:?}"
    );
    assert!(
        seen.contains("/etc/passwd: no such file or directory"),
        "Lua's file access must be mediated by the Shell's VFS, never the host's: {output:?}"
    );
}

/// Lua's `io.popen` and `os.execute` are judged by `shell:exec` — the regression guard for
/// a bypass that was live until 2026-08-08.
///
/// **This was an `#[ignore]`d failing pin.** The attribute came off when the bypass closed;
/// the history is kept because it explains why admission sits where it does.
///
/// The vendored Shell used to admit a command in `Shell::run` → `intercept_shell_command`,
/// while Lua's `io.popen` (`shell/src/builtins/lua.rs:682`) and `os.execute` (`:837`) called
/// `exec::execute_capture` **directly**, performing no admission. So once a policy permitted
/// *any* `lua -e …` command, two lines of Lua ran arbitrary shell text unjudged. Measured
/// 2026-08-07 in a real box: a policy permitting only `lua -e *` and
/// `printf POPEN_ADMITTED_OK` still executed `printf LAUNDERED_VIA_LUA` and returned its
/// output. Both nested commands ran; neither was judged.
///
/// Fixed by option 1 of the three the pin recorded: **admit inside `exec::execute`**, the
/// function every command-text route funnels through, so `find -exec` and `xargs` — which
/// had the same hole and no pin — are closed by the same edit, and a seventh route cannot be
/// added by accident. Options 2 (per entry point) and 3 (drop the `lua` builtin, which needs
/// an upstream `mlua` feature gate) were not taken; 3 is still worth doing separately.
///
/// **Pre-existing, not introduced by hosting the Shell in the daemon**, and verified present at
/// `HEAD` before the move. What the move changed was the *blast radius*: the bypass ran in
/// the process holding the CA key and the resolved secrets rather than in a sibling.
#[test]
fn lua_popen_is_judged_by_policy() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    // Permit the `lua -e` invocations and one inner command, never the laundered one.
    const LUA_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when { context.input.command like "lua -e *" };
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when { context.input.command == "printf POPEN_ADMITTED_OK" };
permit(principal, action == Box::Action::"fs:read", resource);
"#;
    let box_ = box_under(LUA_POLICY, "shell-lua-popen");

    let output = box_.bash(
        r#"zsh -lc 'lua -e "local h=io.popen([[printf POPEN_ADMITTED_OK]]); io.write(h:read([[a]]) or [[empty]])"'
           echo "---"
           zsh -lc 'lua -e "local h=io.popen([[printf LAUNDERED_VIA_LUA]]); io.write(h:read([[a]]) or [[empty]])"'
           echo "---"
           zsh -lc 'lua -e "os.execute([[printf LAUNDERED_VIA_OS_EXECUTE]])"'"#,
    );

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    // Positive half: without it the denials below could pass with `io.popen` absent.
    assert!(
        seen.contains("POPEN_ADMITTED_OK"),
        "io.popen must run a command the policy PERMITS, or this test is vacuous: {output:?}"
    );
    assert!(
        !seen.contains("LAUNDERED_VIA_LUA"),
        "io.popen must not execute a command the policy refuses: {output:?}"
    );
    assert!(
        !seen.contains("LAUNDERED_VIA_OS_EXECUTE"),
        "os.execute must not execute a command the policy refuses: {output:?}"
    );
}

/// `find -exec` and `xargs` are judged per nested command — the siblings that had no pin
/// (docs/design/decisions.md#one-admission-point-after-resolution).
///
/// These are the sharper half of the exec bypass, and they had **no test at all** before
/// 2026-08-08: unlike Lua they are ordinary POSIX tools, so they need no interpreter grant.
/// `find … -exec sh -c '…' \;` was **one** admitted command fanning out to N unjudged ones,
/// which means a policy counting or pattern-matching `shell:exec` saw a single decision for
/// an unbounded number of executions.
///
/// Both halves are asserted, because the negative alone would pass if `find`/`xargs` simply
/// did not work: a *permitted* nested command must still run.
#[test]
fn find_exec_and_xargs_are_judged_per_nested_command() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    // Broad `permit` plus a targeted `forbid`, rather than an enumerated allowlist. A
    // `forbid` is the right shape here for the same reason a budget cap is: it cannot be
    // outrun by a `permit`, and it keeps the test's *subject* — whether the nested command is
    // judged at all — from being confused with whether the fixture's patterns happened to
    // match the exact text the Shell submits (redirects and quoting are part of that text).
    const FANOUT_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
forbid(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when { context.input.command like "*FANOUT_LAUNDERED*" };
permit(principal, action in [Box::Action::"fs:read", Box::Action::"fs:write"], resource);
"#;
    let box_ = box_under(FANOUT_POLICY, "shell-exec-fanout");

    // `-exec … {} ;` and a plain `xargs <cmd>` are the forms this Shell implements —
    // `-exec … \;` needs the semicolon unescaped through two quoting layers, and
    // `xargs -I{}` is unsupported (status 127), so using it would make the negative
    // assertions pass for the wrong reason.
    let home = box_.box_home();
    let home = home.display();
    let output = box_.bash(&format!(
        r#"zsh -lc 'printf FANOUT_SEED > {home}/seed.txt'
           echo "---"
           zsh -lc 'find {home} -name seed.txt -exec printf FANOUT_ADMITTED_OK {{}} ;'
           echo "---"
           zsh -lc 'find {home} -name seed.txt -exec printf FANOUT_LAUNDERED {{}} ;'
           echo "---"
           zsh -lc 'printf {home}/seed.txt | xargs printf FANOUT_LAUNDERED_VIA_XARGS'"#
    ));

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    // Positive half: without it, the denials below could pass because `-exec` never ran.
    assert!(
        seen.contains("FANOUT_ADMITTED_OK"),
        "find -exec must run a nested command the policy PERMITS, or this test is vacuous: {output:?}"
    );
    assert!(
        !seen.contains("FANOUT_LAUNDERED"),
        "find -exec must not execute a nested command the policy refuses: {output:?}"
    );
    assert!(
        !seen.contains("FANOUT_LAUNDERED_VIA_XARGS"),
        "xargs must not execute a nested command the policy refuses: {output:?}"
    );
}

/// A non-yielding Lua loop does not starve the daemon's control socket.
///
/// **The regression guard, and it took three tries to make honest.** An earlier
/// version of this test was vacuous three ways, all worth naming so they are not
/// reintroduced: it probed the broker socket rather than `control.sock` (so it measured the
/// serial worker, not the daemon's liveness); its `sleep 1` spacer was
/// `bash: sleep: command not found`, because containment grants one exec literal; and it
/// used `sleep`, which **yields** — so it could not detect the failure mode even in
/// principle.
///
/// The failure mode is specifically a *non-yielding* interpreter. `mlua`'s interrupt hook
/// (`shell/src/builtins/lua.rs:166-187`) returns `VmState::Continue` synchronously and
/// never awaits, so a Lua loop pins its thread until the command deadline. Measured
/// against the version of this crate that ran the Shell on the daemon's own runtime: an
/// unrelated `run` took **27.73s** and `stop` took 10.09s before escalating to `SIGKILL`.
/// The Shell now has its own thread, so the same probe returns promptly.
///
/// The `stop` half of that measurement is no longer assertable — the verb went with the box
/// namespace it selected — so the second `run` carries the whole property. It is the stronger of
/// the two anyway: it proves a box still serves work, where `stop` proved only that it could die.
///
/// What this asserts is *administrability*, not that the loop is free: it still consumes
/// a core and still blocks the next Shell command until its deadline, because the worker
/// is serial by design.
#[test]
fn a_lua_busy_loop_does_not_starve_the_control_socket() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-no-starve");

    // A Lua loop with no await point anywhere in it, backgrounded so the workload exits
    // while the Shell is still spinning. `&` plus an exit is what leaves the daemon
    // holding a running command with no client attached.
    let spin = box_.bash(
        r#"zsh -lc 'lua -e "while true do end"' >/dev/null 2>&1 &
                            printf SPIN_STARTED"#,
    );
    assert!(
        stdout(&spin).contains("SPIN_STARTED"),
        "the workload must have launched the loop: {spin:?}"
    );

    // The probe: a second `run`, which speaks only to `control.sock` and never touches
    // the broker socket. If the Shell shares the daemon's thread, this waits for the loop's
    // 30s deadline.
    let started = std::time::Instant::now();
    let probe = box_.run(&["/bin/bash", "-c", "printf CONTROL_OK"]);
    let elapsed = started.elapsed();

    assert!(
        stdout(&probe).contains("CONTROL_OK"),
        "the control socket must still serve a run: {probe:?}"
    );
    // Generous by design: this is the difference between "responsive" and "wedged for a
    // command deadline", not a latency budget. The observed regression was 27.73s against
    // a 30s deadline, so anything under a few seconds distinguishes them unambiguously.
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "a Lua busy loop must not starve the control socket; the probe took {elapsed:?} \
         (the pre-fix measurement was 27.73s)"
    );
}

/// The box opens exactly one `Policy`, and the alias image links no authority.
///
/// A source-level guard, because the invariant this whole feature buys is otherwise easy
/// to regress silently: a future integration adds a second `PolicyEngine::open`, every test
/// still passes, and the cross-boundary rules quietly stop enforcing.
///
/// Checked against the source rather than at runtime because "how many instances exist"
/// is not observable from outside the process, and because the failure this prevents is
/// introduced at authoring time.
#[test]
fn the_box_opens_exactly_one_policy() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let mut sites = Vec::new();
    let mut stack = vec![source_root.clone()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory).expect("read source directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            if path == source_root.join("test_support.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source file");
            // Stop at the test *module*, not at any `#[cfg(test)]` — a test-only `use`
            // near the top would otherwise truncate the whole file and make this pass
            // vacuously. That is exactly what the first version of this test did.
            let runtime = match text.find("#[cfg(test)]\nmod tests") {
                Some(boundary) => &text[..boundary],
                None => &text[..],
            };
            for (number, line) in runtime.lines().enumerate() {
                if line.contains("PolicyEngine::open") && !line.trim_start().starts_with("//") {
                    sites.push(format!("{}:{}", path.display(), number + 1));
                }
            }
        }
    }

    assert_eq!(
        sites.len(),
        1,
        "the box must open exactly one PolicyEngine \
         (docs/design/decisions.md#one-policy-engine-per-box); found: {sites:#?}"
    );
    assert!(
        sites[0].contains("run/hosted.rs"),
        "the one Policy must be opened by the box's own trusted half \
         (docs/design/decisions.md#one-trusted-process-per-box), not \
         elsewhere: {sites:#?}"
    );

    // The alias image must not even be able to open one.
    let shim = std::fs::read_to_string(source_root.join("bin/strands-box-sock-alias.rs"))
        .expect("read the shim source");
    assert!(
        !shim.contains("PolicyEngine::open"),
        "the alias image must hold no authority"
    );
    assert!(
        !shim.contains("use policy::"),
        "the alias image must not link the policy crate"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Python through the script broker (docs/design/decisions.md#interpreters-are-brokered-aliases)
// ═══════════════════════════════════════════════════════════════════════════════

/// A policy permitting Python reads and writes inside the box home.
const PYTHON_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
"#;

/// `python3 -c` runs through the broker and its output comes back.
#[test]
fn python_runs_through_the_broker() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PYTHON_POLICY, "monty-runs");

    let output = box_.bash(r#"python3 -c "print('PYTHON_ROUTED_OK')"; echo "status=$?""#);

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        seen.contains("PYTHON_ROUTED_OK"),
        "the script must run in the broker's Monty: {output:?}"
    );
    assert!(
        seen.contains("status=0"),
        "a completed script must exit 0: {output:?}"
    );
}

/// Both `python3` and `python` reach the same broker.
#[test]
fn every_python_alias_reaches_the_broker() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PYTHON_POLICY, "monty-aliases");

    for name in ["python3", "python"] {
        let output = box_.bash(&format!(r#"{name} -c "print('VIA_{name}')""#));
        assert!(
            stdout(&output).contains(&format!("VIA_{name}")),
            "{name} must reach the broker: {output:?}"
        );
    }
}

/// A Python read the policy refuses raises, and reads nothing.
///
/// The point of the whole integration: the interpreter is governed, not merely hosted.
/// Monty performs no I/O of its own — it suspends — so a denial is the broker resuming it
/// with a `PermissionError`, which the script sees as an ordinary Python error.
#[test]
fn python_reads_are_judged_by_policy() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    // Reads permitted only for a `shared-*` name, so a sibling file is refused by the
    // same rule. Scoped by filename rather than by directory because the workload holds
    // one exec literal and no `mkdir` — a `bash` redirect can create a file, not a tree.
    const SCOPED: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.path like "*/shared-*" };
permit(principal, action == Box::Action::"fs:write", resource);
"#;
    let box_ = box_under(SCOPED, "monty-judged");

    let output = box_.bash(
        r#"printf allowed > "$BOX_HOME/shared-ok.txt"
           printf secret > "$BOX_HOME/refused.txt"
           python3 -c "print('READ_OK:' + open('$BOX_HOME/shared-ok.txt').read())"
           python3 -c "
try:
    print('LEAKED:' + open('$BOX_HOME/refused.txt').read())
except PermissionError as error:
    print('DENIED_AS_PYTHON_ERROR')
""#,
    );

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        seen.contains("READ_OK:allowed"),
        "the permitted read must reach the file, or this test is vacuous: {output:?}"
    );
    assert!(
        !seen.contains("LEAKED:secret"),
        "a refused read must not return content: {output:?}"
    );
    assert!(
        seen.contains("DENIED_AS_PYTHON_ERROR"),
        "the denial must arrive as a catchable PermissionError: {output:?}"
    );
}

/// Python cannot reach outside the box home, even when policy would allow it.
///
/// The floor beneath policy, and the reason `script::host` checks the resolved path twice.
/// A permissive policy is used deliberately: what refuses here must be the floor, not the
/// rules — so this fails if the floor is ever removed on the strength of policy.
#[test]
fn python_cannot_escape_the_box_home() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "monty-confined");

    let output = box_.bash(
        r#"python3 -c "
for target in ['/etc/passwd', '../../../../etc/passwd', '/etc/hosts']:
    try:
        open(target).read()
        print('ESCAPED:' + target)
    except Exception as error:
        print('CONFINED:' + target)
""#,
    );

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        !seen.contains("ESCAPED:"),
        "Python must not read outside the box home under any policy: {output:?}"
    );
    assert!(
        seen.contains("CONFINED:/etc/passwd"),
        "the attempt must have been made and refused: {output:?}"
    );
}

/// A Python read closes egress too — the Shell, Monty, and the gateway record into one history.
///
/// **Both boundaries are reached by one run** so the probe fixes their order. It reads the secret
/// itself between its two requests. Port 9 is deliberate: the refusal must come from the boundary,
/// not from a listener.
#[test]
fn a_python_read_closes_egress() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let (host, port) = ("localhost", 9);
    let authority = format!("{host}:{port}");
    let box_ = box_under(
        &format!(
            r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"fs:read", resource);
permit(principal, action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource)
when {{ context.input.host == "{host}" && context.input.port == {port} }}
unless temporal {{
    formerly within 300s
    Box::Action::"fs:read"::response{{ input.path: _, input.operation: Box::FsReadOperation::"read_content" }}
}};
"#
        ),
        "one-policy-python",
    );

    // Planted in a first run: only the READ has to share a history with the egress decision.
    let plant = box_.bash(r#"printf 'super-secret' > "$BOX_HOME/secret""#);
    assert!(
        plant.status.success(),
        "the secret must be planted: {plant:?}"
    );

    let secret = box_.box_home().join("secret");
    let script = format!("data = open('{}').read()", secret.display());
    let output = probe_egress_around_read(&box_, &authority, &["python3", "-c", &script]);
    let seen = format!("{}{}", stdout(&output), stderr(&output));
    eprintln!("CROSS-BOUNDARY (python): {seen}");

    assert!(
        seen.contains("read=ok"),
        "the read must succeed, or the predicate never had a chance to fire: {output:?}"
    );
    assert!(
        !seen.contains("status=403"),
        "egress must be permitted before the read, or the rule below proves nothing: {output:?}"
    );
    assert!(
        seen.contains("status_after=403"),
        "egress must close once the secret is read; two histories leave it open: {output:?}"
    );
}

/// An unbounded Python loop is stopped by the interpreter, not left running.
///
/// The regression guard for a defect this module shipped and an altitude review caught:
/// `SCRIPT_TIMEOUT` was applied as a `tokio::time::timeout` around Monty's run loop, which
/// has **no await points** — so the timer could never fire and `while True: pass` pinned
/// the broker thread indefinitely. The bound now lives inside the VM (`ResourceTracker`),
/// which checks it from its own loop.
///
/// Asserted by wall clock rather than by message, because what matters is that it *stops*.
/// The script's own deadline is 120s and the request bound is 300s, so anything under 130s
/// means the interpreter stopped itself; a hang would sit here until the test harness gave
/// up. Also asserts the box is still administrable afterwards — a bound that stopped the
/// script but left the thread wedged would pass a timing check alone.
#[test]
fn an_unbounded_python_loop_is_stopped() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PYTHON_POLICY, "monty-bounded");

    let started = std::time::Instant::now();
    let output = box_.bash(
        r#"python3 -c "
while True:
    pass
"; echo "status=$?""#,
    );
    let elapsed = started.elapsed();

    assert!(
        elapsed < std::time::Duration::from_secs(130),
        "an unbounded script must be stopped by the interpreter; it ran for {elapsed:?}"
    );
    assert!(
        stdout(&output).contains("status="),
        "the alias must report a status rather than hanging: {output:?}"
    );

    // And the broker still serves, so the bound cost that script and not the box.
    let after = box_.bash(r#"python3 -c "print('STILL_SERVING')""#);
    assert!(
        stdout(&after).contains("STILL_SERVING"),
        "the broker must survive a stopped script: {after:?}"
    );
}

/// A file handle does not become an unmediated channel.
///
/// The arm I was least sure of. `open()` returns a `MontyFileHandle` — a *value* carrying a
/// path, a mode, and a position — and the broker records `DescriptorIssued` rather than
/// `Completed` because no bytes have moved yet. The property that makes that safe is that
/// Monty's file methods suspend again for each read and write, so every one arrives back for
/// its own admission. This asserts that rather than trusting it: a handle opened for a
/// *permitted* path must not be usable to reach a refused one, and a write through a
/// read-mode handle must not land.
#[test]
fn a_file_handle_does_not_escape_the_floor() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const READ_ONLY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"fs:read", resource);
"#;
    let box_ = box_under(READ_ONLY, "monty-handle");

    let output = box_.bash(
        r#"printf 'contents' > "$BOX_HOME/readable.txt"
           python3 -c "
handle = open('$BOX_HOME/readable.txt')
print('OPEN_OK:' + handle.read())
try:
    out = open('$BOX_HOME/written.txt', 'w')
    out.write('should not land')
    print('WROTE_WITHOUT_PERMIT')
except Exception as error:
    print('WRITE_REFUSED')
""#,
    );

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        seen.contains("OPEN_OK:contents"),
        "a permitted read through a handle must work, or this test is vacuous: {output:?}"
    );
    assert!(
        !seen.contains("WROTE_WITHOUT_PERMIT"),
        "a write must be refused with no fs:write permit, handle or not: {output:?}"
    );
    assert!(
        seen.contains("WRITE_REFUSED"),
        "the refusal must reach the script as a catchable error: {output:?}"
    );
}

/// A symlink the script itself creates cannot be followed out of the home.
///
/// The sharpest attack on the floor, and a genuine time-of-check/time-of-use shape: nothing
/// stops a script from creating a link inside its own home and then opening it, so the floor
/// must resolve at *use* rather than trusting an earlier check. `confine` canonicalizes on
/// every effect, which is what closes it — this asserts the closure rather than the intent.
///
/// A permissive policy on purpose: what refuses here must be the floor. If policy were the
/// thing refusing, the test would pass while the floor was broken.
#[test]
fn a_symlink_out_of_the_home_is_not_followed() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "monty-symlink");

    let output = box_.bash(
        r#"ln -s /etc/passwd "$BOX_HOME/escape" 2>/dev/null || printf 'LN_UNAVAILABLE\n'
           python3 -c "
for target in ['$BOX_HOME/escape', '$BOX_HOME/../../../../etc/passwd']:
    try:
        data = open(target).read()
        print('ESCAPED:' + target)
    except Exception as error:
        print('CONFINED:' + target)
""#,
    );

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        !seen.contains("ESCAPED:"),
        "no path may resolve outside the box home, however it is spelled: {output:?}"
    );
    assert!(
        seen.contains("CONFINED:"),
        "the attempts must have been made and refused: {output:?}"
    );
}

/// An interpreter rename refuses a destination outside its reachable roots.
#[test]
fn a_rename_moves_within_the_home_and_is_refused_outside_reach() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "monty-rename");
    let outside = fixture::short_temporary_home();
    let escape = outside.path().join("escape.txt");
    let control = box_.box_home().join("rename-control");
    std::fs::write(&control, "control").expect("an uncontained source");
    std::fs::rename(&control, outside.path().join("control"))
        .expect("an uncontained rename can cross these directories");

    // Inside the home: the move performs, keeps the bytes, and removes the source.
    let inside = box_.bash(
        r#"printf 'original' > "$BOX_HOME/source.txt"
           python3 -c "
from pathlib import Path
Path('$BOX_HOME/source.txt').rename('$BOX_HOME/moved.txt')
if Path('$BOX_HOME/moved.txt').read_text() == 'original':
    print('MOVED')
else:
    print('CONTENT_LOST')
if Path('$BOX_HOME/source.txt').exists():
    print('SOURCE_STILL_THERE')
else:
    print('SOURCE_GONE')
""#,
    );
    let seen = format!("{}{}", stdout(&inside), stderr(&inside));
    assert!(
        seen.contains("MOVED"),
        "a rename inside the home must move the file and keep its bytes: {inside:?}"
    );
    assert!(
        seen.contains("SOURCE_GONE"),
        "a completed move must remove the source: {inside:?}"
    );

    let across = box_.bash(&format!(
        r#"printf 'original' > "$BOX_HOME/keep.txt"
           python3 -c "
from pathlib import Path
try:
    Path('$BOX_HOME/keep.txt').rename('{}')
    print('ESCAPED')
except Exception as error:
    print('REFUSED')
if Path('$BOX_HOME/keep.txt').read_text() == 'original':
    print('SOURCE_STILL_THERE')
else:
    print('SOURCE_GONE')
""#,
        escape.display()
    ));
    let seen = format!("{}{}", stdout(&across), stderr(&across));
    assert!(
        !seen.contains("ESCAPED"),
        "a rename outside the interpreter's reachable roots must be refused: {across:?}"
    );
    assert!(
        seen.contains("REFUSED"),
        "the refusal must reach the script as a catchable error: {across:?}"
    );
    assert!(
        seen.contains("SOURCE_STILL_THERE"),
        "a refused rename must leave the source untouched: {across:?}"
    );
    assert!(
        !escape.exists(),
        "the refused destination must remain absent"
    );
    assert_eq!(
        std::fs::read_to_string(box_.box_home().join("keep.txt")).unwrap(),
        "original"
    );
}

/// A **dangling** symlink cannot be written through, out of the box home.
///
/// **The regression guard for a verified sandbox escape.** `canonicalize` fails with
/// `ENOENT` on a dangling symlink — the link exists as a directory entry, only its target
/// does not — so the create path in `confine` re-attached the leaf name, `starts_with`
/// passed, and `fs::write` followed the link out of the box with the *daemon's* authority.
///
/// `a_symlink_out_of_the_home_is_not_followed` misses this entirely, because it links to an
/// **existing** target (`/etc/passwd`), which canonicalizes and is correctly refused. The gap
/// was create-a-file-that-does-not-exist-yet. Both tests are kept: they cover the two arms of
/// `confine`, and only one of them ever failed.
///
/// The link is planted by the *test*, not by the workload, and that is the stronger claim:
/// the workload's home is blanket `file-write*`, so a link appearing there needs no
/// privilege — but the workload holds one exec literal and no `ln`, which is a limit on this
/// suite rather than on an attacker. Planting it directly asserts the floor holds against a
/// link *however it arrived*.
///
/// A permissive policy on purpose — what must refuse here is the floor, not the rules.
#[test]
fn a_dangling_symlink_cannot_be_written_through() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "monty-dangling");

    // Outside the box, and absent — so the link dangles and `canonicalize` fails on it.
    let target = box_.operator_home().join("OPERATOR_OWNED_BY_MONTY.txt");
    assert!(!target.exists(), "the fixture target must start absent");
    let link = box_.box_home().join("escape.txt");
    std::os::unix::fs::symlink(&target, &link).expect("plant the dangling link");

    let output = box_.bash(
        r#"python3 -c "
from pathlib import Path
try:
    Path('$BOX_HOME/escape.txt').write_text('PWNED_BY_MONTY')
    print('WROTE_THROUGH_LINK')
except Exception as error:
    print('REFUSED')
""#,
    );

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        !target.exists(),
        "SANDBOX ESCAPE: Monty wrote outside the box home through a dangling symlink — {} \
         now exists: {output:?}",
        target.display()
    );
    assert!(
        !seen.contains("WROTE_THROUGH_LINK"),
        "a write through a dangling link must not report success: {output:?}"
    );
    assert!(
        seen.contains("REFUSED"),
        "the refusal must reach the script as a catchable error: {output:?}"
    );
}

/// An intra-home symlink cannot launder a path-scoped read.
///
/// **The regression guard for the second floor defect.** `ScriptPolicyInterceptor` resolves
/// paths *lexically* — it never touches the filesystem — so a link at a permitted spelling is
/// judged on the link while the effect reads its target. The adapter documents that and says
/// containment covers it "by confining the workload to a subtree that contains no links out
/// of it". That argument held for the Shell, whose effects run with the *workload's*
/// authority. It does not transfer to Monty, which runs with the daemon's — and the link here
/// does not point *out* of the home, it points *within* it, so the home-confinement floor
/// never fires.
///
/// The escape: `permit fs:read when path like "*/shared-*"` plus a link
/// `home/shared-alias -> home/secret.txt` reads the secret under a rule that names only
/// `shared-*`. Closed by refusing a path whose canonical identity differs from the one policy
/// judged.
#[test]
fn an_intra_home_symlink_cannot_launder_a_scoped_read() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    // Reads permitted only for a `shared-*` name. Both files are inside the home, so the
    // home floor is irrelevant here — only the rule stands between them.
    const SCOPED: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.path like "*/shared-*" };
permit(principal, action == Box::Action::"fs:write", resource);
"#;
    let box_ = box_under(SCOPED, "monty-launder");

    // Planted by the test: the workload holds one exec literal and no `ln`, which is a limit
    // on this suite rather than on an attacker — its home is blanket `file-write*`.
    std::fs::write(box_.box_home().join("secret.txt"), b"POLICY-FORBIDS-THIS")
        .expect("stage the secret");
    std::os::unix::fs::symlink("secret.txt", box_.box_home().join("shared-alias"))
        .expect("plant the intra-home link");
    std::fs::write(box_.box_home().join("shared-ok.txt"), b"allowed")
        .expect("stage a permitted file");

    let output = box_.bash(
        r#"python3 -c "
print('DIRECT_OK:' + open('$BOX_HOME/shared-ok.txt').read())
try:
    print('LAUNDERED:' + open('$BOX_HOME/shared-alias').read())
except Exception as error:
    print('LAUNDER_REFUSED')
""#,
    );

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    // Without this, the refusal below could mean `fs:read` is broken outright.
    assert!(
        seen.contains("DIRECT_OK:allowed"),
        "a permitted read must still work, or this test is vacuous: {output:?}"
    );
    assert!(
        !seen.contains("POLICY-FORBIDS-THIS"),
        "a link at a permitted spelling must not read a path the rule excludes: {output:?}"
    );
    assert!(
        seen.contains("LAUNDER_REFUSED"),
        "the refusal must reach the script as a catchable error: {output:?}"
    );
}

/// **The workspace is readable at its real path, through an interpreter.**
///
/// The old test asserted a `[[bind]]` was readable at its mount point `/<at>`. `[[bind]]` was
/// removed with the shared home, so there is no mount point — the interpreters see the operator's
/// whole home beneath the deny floor, and the workspace is reachable at the path the operator wrote.
///
/// The rename the mount point provided is genuinely lost: a rule names `~/workspace/service`
/// rather than `/workspace`, so a policy is portable only where the path under the home matches.
/// It is a cost rather than an oversight.
#[test]
fn the_project_is_readable_at_its_real_path_through_an_interpreter() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-workspace-path");
    let workspace = box_.operator_home().join("workspace/service");
    std::fs::create_dir_all(&workspace).expect("a workspace in the operator's home");
    std::fs::write(workspace.join("README.md"), "PROJECT_CONTENT").expect("a workspace file");

    let output = box_.bash(&format!(
        r#"zsh -lc "cat {}" 2>&1"#,
        workspace.join("README.md").display()
    ));
    assert!(
        stdout(&output).contains("PROJECT_CONTENT"),
        "the workspace must be readable at its real path through the shell alias: {output:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Passthrough: a host binary, judged as `shell:spawn`
// ═══════════════════════════════════════════════════════════════════════════════

/// A policy permitting every program the Shell implements, and exactly one host binary.
///
/// `hostname` rather than `git`: this suite must not depend on a developer tool being installed.
/// `hostname` ships with macOS and every supported Linux, and the Shell does not implement it —
/// so it is a real host binary on every host this runs on.
const ONE_BINARY_POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "hostname" };
permit(principal, action == Box::Action::"fs:read", resource);
"#;

/// `hostname` as a declared tool with no filesystem of its own: it prints and reaches nothing.
///
/// Declared under every policy below, so the pairs differ in one *rule* and nothing else: a tool
/// the configuration names still runs only where `shell:spawn` permits it.
const HOSTNAME_TOOL: &str = "[tool.hostname]\ncommand = [\"hostname\"]\n";

/// `dd` as a declared tool holding the project read-write; `write` no longer implies `read`.
const DD_TOOL: &str = "[tool.dd]\ncommand = [\"dd\"]\n[tool.dd.filesystem]\n\
                       read = [\"{workspace}\"]\nwrite = [\"{workspace}\"]\n";

/// The egress probe as a declared tool with no filesystem: it dials and touches no path.
const PROBE_TOOL: &str = "[tool.probe]\ncommand = [\"box-egress-probe\"]\n";

/// The egress probe as a declared tool holding the project read-write, for the authority probes.
const PROBE_WRITER_TOOL: &str = "[tool.probe]\ncommand = [\"box-egress-probe\"]\n\
                                 [tool.probe.filesystem]\nread = [\"{workspace}\"]\n\
                                 write = [\"{workspace}\"]\n";

/// A policy permitting the Shell's own programs and **no** host binary.
///
/// The control for the pair below: the same command, the same `PATH`, one rule different.
const NO_BINARY_POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"fs:read", resource);
"#;

/// A policy permitting the Shell's own programs, one host binary that writes, and every `fs:*`.
///
/// **`fs:write` is permitted deliberately.** A refusal below therefore cannot be the policy or the
/// Shell's own floor: what refuses it is the leaf box's containment. `dd` rather than `tee`, because
/// the Shell implements `tee` and would mediate the write instead of spawning a leaf.
const ONE_WRITER_POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "dd" };
permit(principal, action == Box::Action::"fs:read", resource);
permit(principal, action == Box::Action::"fs:write", resource);
"#;

/// A test-before-commit rule: `git commit` is refused unless a `cargo test` spawn completed, as a
/// `shell:spawn::response`, within the last 600 s.
const TEST_BEFORE_COMMIT_POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "git" || context.input.program == "cargo" };
@id("test_before_commit")
forbid(principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "git" && context.input has arg1 && context.input.arg1 == "commit" }
unless temporal {
    formerly within 600s (
        Box::Action::"shell:spawn"::response{ input.program: "cargo", input.arg1: "test" }
    )
};
"#;

/// Two probe programs declared as the tools a test-before-commit rule names, each reading the
/// probe directory its `#!` interpreter opens.
const PROBE_TOOLCHAIN: &str = "[tool.git]\ncommand = [\"git\"]\n[tool.git.filesystem]\n\
                               read = [\"{box_home}/probe-bin\"]\n\n\
                               [tool.cargo]\ncommand = [\"cargo\"]\n[tool.cargo.filesystem]\n\
                               read = [\"{box_home}/probe-bin\"]\n";

/// Place a probe program named `name` in `bin` that prints `<NAME>_RAN` and its arguments.
fn install_probe_program(bin: &std::path::Path, name: &str) {
    let path = bin.join(name);
    std::fs::write(
        &path,
        format!(
            "#!/bin/bash\nprintf '{}_RAN %s\\n' \"$*\"\n",
            name.to_uppercase()
        ),
    )
    .expect("write the probe program");
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("make the probe program executable");
}

/// A `shell:spawn` decision keys on a prior `shell:spawn::response`: the first commit is refused,
/// the test run completes, and the same commit is then permitted.
#[test]
fn a_spawn_rule_keyed_on_a_prior_spawn_response_lifts_only_after_the_test_run_completes() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let request = Request::with_config(
        "spawn-test-before-commit",
        TEST_BEFORE_COMMIT_POLICY,
        PROBE_TOOLCHAIN,
    );
    // Under the agent home the fixture declares, so the tool tables above can name it.
    let bin = request.operator_home().join("agent-home/probe-bin");
    std::fs::create_dir_all(&bin).expect("the probe directory");
    install_probe_program(&bin, "git");
    install_probe_program(&bin, "cargo");
    // The probes are not on the system PATH; put their directory first so `shell:spawn` resolves
    // each by bare name against the operator's real host PATH.
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())
    );
    let box_ = request.env("PATH", &path).expect();

    let output = box_.bash(
        r#"zsh -lc "git commit -m fix"; echo "first=$?"
           zsh -lc "cargo test"; echo "test=$?"
           zsh -lc "git commit -m fix"; echo "second=$?""#,
    );
    let seen = stdout(&output);
    let errors = stderr(&output);

    assert!(
        seen.contains(&format!("first={DENIED_STATUS}")),
        "the commit before any test run must be refused: {output:?}"
    );
    assert!(
        errors.contains("test_before_commit"),
        "the refusal must name the rule: {output:?}"
    );
    assert!(
        seen.contains("CARGO_RAN test") && seen.contains("test=0"),
        "the test run must complete: {output:?}"
    );
    assert!(
        seen.contains("GIT_RAN commit -m fix") && seen.contains("second=0"),
        "the commit after the test run must be permitted: {output:?}"
    );
    assert_eq!(
        seen.matches("GIT_RAN").count(),
        1,
        "exactly one commit runs: {output:?}"
    );
}

/// **A leaf box cannot write the project's own `.strands-box`, and the control proves the grant it
/// is subtracted from is really there.**
///
/// A leaf runs a host binary with raw syscalls and no `fs:*` decision, so containment
/// is the only thing between it and the `policy.dw` that governs the next run of this box. The
/// control is not optional: without it this test passes on a leaf that was never granted the project
/// at all, which is the shape the unit test beside it also guards against.
#[test]
fn a_leaf_box_cannot_write_the_projects_own_authority() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let box_ = Request::with_config("leaf-authority", ONE_WRITER_POLICY, DD_TOOL).expect();

    // The project holds a box's authority, as every real project does.
    let authority = box_.workspace().join(".strands-box");
    std::fs::create_dir_all(&authority).expect("the project's own authority directory");
    let policy = authority.join("policy.dw");
    let policy_before = std::fs::read_to_string(&policy).expect("the loaded policy");
    // A seed the host binary copies FROM, because a leaf host binary receives no piped stdin —
    // measured: `echo x | dd` reports `0+0 records in` inside a leaf.
    std::fs::write(box_.workspace().join("seed.txt"), "LEAF_WROTE_THIS\n").expect("a seed to copy");

    // The control: the same host binary writes an ordinary file in the project, which must land.
    let control = box_.bash(r#"zsh -lc "dd if={workspace}/seed.txt of={workspace}/ok.txt""#);
    let landed = std::fs::read_to_string(box_.workspace().join("ok.txt")).unwrap_or_default();
    assert!(
        landed.contains("LEAF_WROTE_THIS"),
        "the control must land, or this test proves nothing about the subtraction: {control:?}"
    );

    // The subject: writing the box's own policy must change nothing on the host.
    let attempt =
        box_.bash(r#"zsh -lc "dd if={workspace}/seed.txt of={workspace}/.strands-box/policy.dw""#);
    let after = std::fs::read_to_string(&policy).expect("the policy is still readable");
    assert!(
        after == policy_before,
        "a leaf box must not write the policy that governs the next run of this box: \
         {attempt:?}\nthe policy now reads: {after}"
    );
}

/// A permitted host binary runs, and its output reaches the caller.
///
/// The output half is not incidental. Inheriting the child's stdio made this exact case
/// return status 0 while printing **nothing** to the caller — the bytes went to the daemon's
/// own stdout, which is its log file. So asserting the status alone would have passed against
/// that defect.
#[test]
fn a_permitted_host_binary_runs_and_its_output_returns() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_config("spawn-permitted", ONE_BINARY_POLICY, HOSTNAME_TOOL).expect();

    let output = box_.bash(r#"zsh -lc "hostname""#);

    assert!(
        !stdout(&output).trim().is_empty(),
        "a permitted host binary's stdout must reach the caller, not the daemon's log: \
         {output:?}"
    );
    assert!(output.status.success(), "{output:?}");
}

#[test]
#[cfg(target_os = "macos")]
fn a_matching_leaf_reads_and_writes_announced_credentials_and_the_main_workload_does_not() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource)
when {
    context.input.program == "wc" &&
    context.input has credential_reads &&
    context.input.credential_reads.contains("~/.aws")
};
permit(principal, action == Box::Action::"shell:spawn", resource)
when {
    context.input.program == "touch" &&
    context.input has credential_reads &&
    context.input.credential_reads.contains("~/.aws/sso/cache")
};
permit(
    principal,
    action in [Box::Action::"fs:read", Box::Action::"fs:write"],
    resource
);
"#;
    let request = Request::with_config(
        "tool-credential-read",
        POLICY,
        r#"
[tool.wc]
command = ["wc"]
[tool.wc.filesystem]
read = ["~/.aws"]

[tool.touch]
command = ["touch"]
[tool.touch.filesystem]
write = ["~/.aws/sso/cache"]
"#,
    );
    let credential = request.operator_home().join(".aws/credentials");
    std::fs::create_dir_all(credential.parent().expect("the credential has a parent"))
        .expect("create the credential store");
    std::fs::write(&credential, "LEAF_CREDENTIAL_BYTES\n").expect("write the credential");
    let cache = request.operator_home().join(".aws/sso/cache");
    std::fs::create_dir_all(&cache).expect("create the credential cache");
    let main_write = cache.join("main-write");
    let leaf_write = cache.join("leaf-write");
    let box_ = request.expect();

    let output = box_.bash(&format!(
        r#"
if IFS= read -r leaked < "{path}"; then
    printf 'MAIN_LEAK=%s\n' "$leaked"
else
    printf 'MAIN_DENIED\n'
fi
if printf main > "{main_write}"; then
    printf 'MAIN_WRITE_ALLOWED\n'
else
    printf 'MAIN_WRITE_DENIED\n'
fi
zsh -lc 'wc -c "{path}"'
zsh -lc 'touch "{leaf_write}"'
"#,
        path = credential.display(),
        main_write = main_write.display(),
        leaf_write = leaf_write.display()
    ));
    let seen = stdout(&output);
    let errors = stderr(&output);

    assert!(
        seen.contains("MAIN_DENIED") && !seen.contains("LEAF_CREDENTIAL_BYTES"),
        "the main workload must not read the credential: {output:?}"
    );
    assert!(
        seen.contains("MAIN_WRITE_DENIED") && !main_write.exists(),
        "the main workload must not write the credential cache: {output:?}"
    );
    assert!(
        seen.contains("22 "),
        "the selected wc leaf must read all credential bytes: {output:?}"
    );
    assert!(
        leaf_write.exists(),
        "the selected touch leaf must write the credential cache: {output:?}"
    );
    let read_announcement = errors
        .find("strands-box: [tool.wc]: exposes ~/.aws (read)")
        .expect("the read announcement is present");
    let write_announcement = errors
        .find("strands-box: [tool.touch]: exposes ~/.aws/sso/cache (write)")
        .expect("the write announcement is present");
    let started_at = errors
        .find("strands-box: starting workload")
        .expect("the workload start line is present");
    assert!(
        read_announcement < started_at && write_announcement < started_at,
        "the credential announcements must precede the workload: {output:?}"
    );
    assert!(output.status.success(), "{output:?}");
}

/// **The security property.** The same binary, the same `PATH`, no `shell:spawn` rule — refused.
///
/// Paired with the test above deliberately: alone, either one passes for the wrong reason. This
/// one would pass if passthrough were simply unbuilt, and that one would pass if every binary
/// ran regardless of policy. Together they show the *rule* is what decides.
#[test]
fn a_host_binary_without_a_spawn_permit_is_denied() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_config("spawn-denied", NO_BINARY_POLICY, HOSTNAME_TOOL).expect();

    let output = box_.bash(r#"zsh -lc "hostname && printf SPAWN_RAN""#);

    assert!(
        !stdout(&output).contains("SPAWN_RAN"),
        "a host binary with no shell:spawn permit must not run: {output:?}"
    );
    assert!(
        stderr(&output).contains("denied"),
        "the refusal must say it was denied: {output:?}"
    );
}

/// A `shell:exec` permit is not a `shell:spawn` permit, even unconditional.
///
/// `NO_BINARY_POLICY`'s first rule permits `shell:exec` with no `when` at all. If the two actions
/// were one action with a flag, that rule would grant host-binary execution — which is the
/// upgrade fail-open the split exists to prevent, and the reason
/// `policy/tests/shell_resolved_actions.rs` pins it at the policy level too. This is the same
/// property end to end, through a real box.
#[test]
fn an_unconditional_run_permit_does_not_grant_a_host_binary() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_config("spawn-not-run", NO_BINARY_POLICY, HOSTNAME_TOOL).expect();

    // The control: a program the Shell *does* implement is permitted by the same rule.
    let permitted = box_.bash(r#"zsh -lc "printf RUN_PERMITTED""#);
    assert!(
        stdout(&permitted).contains("RUN_PERMITTED"),
        "the unconditional shell:exec permit must still grant the Shell's own programs: \
         {permitted:?}"
    );

    // The property: the same permit does not reach a host binary.
    let refused = box_.bash(r#"zsh -lc "hostname""#);
    assert!(
        !refused.status.success(),
        "an unconditional shell:exec permit must not grant a host binary: {refused:?}"
    );
}

/// A program on no `PATH` is still **not found**, never a denial.
///
/// Passthrough is tried *before* giving up rather than replacing the 127 path, so the three
/// outcomes stay distinguishable: denied, the binary's own status, and absent. Collapsing absent
/// into denied would tell an operator their policy refused something that was never there.
#[test]
fn a_program_that_exists_nowhere_is_not_found_rather_than_denied() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_config("spawn-absent", ONE_BINARY_POLICY, HOSTNAME_TOOL).expect();

    let output = box_.bash(r#"zsh -lc "definitely-not-a-real-program-xyz""#);

    let stderr = stderr(&output);
    assert!(
        stderr.contains("not found"),
        "an absent program must report not-found: {output:?}"
    );
    assert!(
        !stderr.contains("denied"),
        "an absent program must not be reported as a policy denial: {output:?}"
    );
}

/// A host binary's egress in a leaf is judged by the gateway (live end to end).
///
/// The construction test `boundary.rs::a_leaf_boxs_egress_is_forced_to_the_parent_gateway` pins
/// that a leaf's network posture is forced onto the parent gateway; this runs it through a real
/// box. `box-egress-probe` is resolved on the operator's host `PATH` and run as a
/// host binary, so it goes `shell:spawn` → the contained leaf, then dials the gateway. The policy
/// permits the spawn but names **no** `net:connect`, so the gateway refuses the leaf's CONNECT with
/// `403`. `status=403` proves two things at once: the probe **ran** (the spawn reached the leaf)
/// and its **egress was judged and refused by the gateway** — a leaf has no ungoverned network.
#[test]
fn a_leaf_boxs_egress_is_judged_by_the_gateway() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    // The probe is not on the system PATH; put its directory first so `shell:spawn` resolves it by
    // bare name against the operator's real host PATH.
    let probe = std::path::Path::new(env!("CARGO_BIN_EXE_box-egress-probe"));
    let probe_dir = probe.parent().expect("the probe has a parent directory");
    let path = format!(
        "{}:{}",
        probe_dir.display(),
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())
    );
    const POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "box-egress-probe" };
"#;
    let box_ = Request::with_config("leaf-egress-judged", POLICY, PROBE_TOOL)
        .env("PATH", &path)
        .expect();

    // `localhost:9` resolves (so DNS does not 502 before the decision) and is not SSRF-floored, so
    // the CONNECT reaches the Cedar `net:connect` check — which default-denies, since the policy
    // names no `net:connect`. Port 9 has no listener, but the refusal is the boundary's, not a
    // missing listener's. This mirrors `no_egress_after_secret_read`.
    let output = box_.bash(r#"zsh -lc "box-egress-probe https://localhost:9/v1/upload HOME""#);

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        seen.contains("status=403"),
        "the leaf's egress must be judged and refused by the gateway (403 at CONNECT), which also \
         proves the probe ran in the leaf: {output:?}"
    );
}

/// The exit probe as a declared tool with no filesystem.
const EXIT_PROBE_TOOL: &str = "[tool.exit-probe]\ncommand = [\"box-exit-probe\"]\n";

/// A box that spawns `box-exit-probe` and gates `printf <name>` on each listed probe status.
///
/// The probe resolves by bare name on the host `PATH`, and each gate pins its `program_path`.
fn exit_probe_box(name: &str, gates: &[(&str, i32)]) -> Configured {
    let probe = std::path::Path::new(env!("CARGO_BIN_EXE_box-exit-probe"))
        .canonicalize()
        .expect("the exit probe resolves");
    let probe_dir = probe.parent().expect("the probe has a parent directory");
    let path = format!(
        "{}:{}",
        probe_dir.display(),
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())
    );
    let mut policy = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "box-exit-probe" };
"#
    .to_string();
    for (gate, status) in gates {
        policy.push_str(&format!(
            r#"
@id("{gate}")
forbid(principal, action == Box::Action::"shell:exec", resource)
when {{ context.input.command == "printf {gate}" }}
unless temporal {{
    formerly within 60s
    Box::Action::"shell:spawn"::response{{ input.program_path: "{probe}", output.status: {status} }}
}};
"#,
            probe = probe.display()
        ));
    }
    Request::with_config(name, &policy, EXIT_PROBE_TOOL)
        .env("PATH", &path)
        .expect()
}

#[test]
fn a_spawned_host_binary_records_its_non_zero_exit_in_history() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = exit_probe_box(
        "spawn-exit-status",
        &[("after-three", 3), ("after-zero", 0)],
    );

    let output = box_.bash(
        r#"zsh -lc "box-exit-probe exit 3"; echo "probe=$?"
           zsh -lc "printf after-three"; echo " three=$?"
           zsh -lc "printf after-zero"; echo " zero=$?""#,
    );

    let stdout = stdout(&output);
    assert!(
        stdout.contains("probe=3"),
        "the probe must run in its leaf and exit 3: {output:?}"
    );
    assert!(
        stdout.contains("after-three three=0"),
        "an exit of 3 must satisfy `output.status: 3`: {output:?}"
    );
    assert!(
        stdout.contains(&format!("zero={DENIED_STATUS}")),
        "an exit of 3 must not satisfy `output.status: 0`: {output:?}"
    );
}

#[test]
fn a_signalled_host_binary_records_128_plus_the_signal_in_history() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let killed = 128 + libc::SIGKILL;
    let box_ = exit_probe_box(
        "spawn-signal-status",
        &[("after-kill", killed), ("after-nine", libc::SIGKILL)],
    );

    let output = box_.bash(&format!(
        r#"zsh -lc "box-exit-probe signal {signal}"; echo "probe=$?"
           zsh -lc "printf after-kill"; echo " kill=$?"
           zsh -lc "printf after-nine"; echo " nine=$?""#,
        signal = libc::SIGKILL
    ));

    let stdout = stdout(&output);
    assert!(
        stdout.contains(&format!("probe={killed}")),
        "the probe must end by SIGKILL and report {killed}: {output:?}"
    );
    assert!(
        stdout.contains("after-kill kill=0"),
        "a SIGKILL must record `output.status: {killed}`: {output:?}"
    );
    assert!(
        stdout.contains(&format!("nine={DENIED_STATUS}")),
        "a SIGKILL must not record the bare signal number: {output:?}"
    );
}

#[test]
fn a_contained_host_binary_cannot_change_loaded_authority_sources() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let probe = std::path::Path::new(env!("CARGO_BIN_EXE_box-egress-probe"));
    let probe_dir = probe.parent().expect("the probe has a parent directory");
    let path = format!(
        "{}:{}",
        probe_dir.display(),
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())
    );
    const POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "box-egress-probe" };
"#;
    let box_ = Request::with_config("leaf-authority-protected", POLICY, PROBE_WRITER_TOOL)
        .env("PATH", &path)
        .expect();
    box_.write_command("/bin/bash");
    let config = box_.config().to_path_buf();
    let policy = box_.workspace().join(".strands-box/policy.dw");
    let replacement = box_.workspace().join("replacement");
    let alias = box_.workspace().join("authority-alias");
    std::fs::write(&replacement, "replacement").expect("replacement fixture");
    let config_before = std::fs::read(&config).expect("read config source");
    let policy_before = std::fs::read(&policy).expect("read policy source");

    let output = box_.bash(&format!(
        "zsh -lc \"box-egress-probe protect-authority '{}' '{}' '{}' '{}'\"",
        config.display(),
        policy.display(),
        replacement.display(),
        alias.display()
    ));

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    for expected in [
        "write=refused",
        "delete=refused",
        "replace=refused",
        "link=refused",
    ] {
        assert!(
            seen.contains(expected),
            "{expected}: the contained host binary changed loaded authority: {output:?}"
        );
    }
    assert_eq!(std::fs::read(&config).expect("read config"), config_before);
    assert_eq!(std::fs::read(&policy).expect("read policy"), policy_before);
    assert_eq!(
        std::fs::read_to_string(&replacement).expect("replacement remains"),
        "replacement"
    );
    assert!(!alias.exists(), "the protected object gained an alias");
}

#[test]
fn a_contained_host_binary_cannot_move_an_authority_sources_parent() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let probe = std::path::Path::new(env!("CARGO_BIN_EXE_box-egress-probe"));
    let probe_dir = probe.parent().expect("the probe has a parent directory");
    let path = format!(
        "{}:{}",
        probe_dir.display(),
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())
    );
    const POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "box-egress-probe" };
"#;
    let box_ = Request::with_config("leaf-auth-parent", POLICY, PROBE_WRITER_TOOL)
        .env("PATH", &path)
        .expect();
    let source = box_.workspace().join("authority");
    let destination = box_.workspace().join("authority-moved");
    std::fs::create_dir(&source).expect("authority directory");
    // The copied configuration runs `bash`, so the second `run` below appends only `-c`.
    box_.write_command("/bin/bash");
    let mut selected_config: toml::Value =
        toml::from_str(&std::fs::read_to_string(box_.config()).expect("read config"))
            .expect("parse config");
    selected_config["tool"]["probe"]["filesystem"]
        .as_table_mut()
        .expect("the tool has filesystem lists")
        .insert(
            "deny".into(),
            toml::Value::Array(vec![source.join("policy.dw").display().to_string().into()]),
        );
    let config_before = toml::to_string(&selected_config)
        .expect("serialize the selected config")
        .into_bytes();
    let policy_before =
        std::fs::read(box_.workspace().join(".strands-box/policy.dw")).expect("read policy");
    std::fs::write(source.join("box.toml"), &config_before).expect("selected configuration");
    std::fs::write(source.join("policy.dw"), &policy_before).expect("selected policy");
    let control_source = box_.workspace().join("control");
    let control_destination = box_.workspace().join("control-moved");
    std::fs::create_dir(&control_source).expect("control directory");
    std::fs::write(control_source.join("box.toml"), &config_before).expect("control config");
    let control = std::process::Command::new(probe)
        .arg("move-authority-parent")
        .arg(&control_source)
        .arg(&control_destination)
        .arg("box.toml")
        .output()
        .expect("uncontained control");
    assert!(control.status.success(), "{control:?}");
    for expected in [
        "sibling_mutation=allowed",
        "parent_move=allowed",
        "source_replacement=allowed",
    ] {
        assert!(
            stdout(&control).contains(expected),
            "{expected}: {control:?}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(control_source.join("box.toml")).expect("replacement"),
        "replacement"
    );

    let output = std::process::Command::new(fixture::box_binary())
        .arg("run")
        .arg("--config")
        .arg(source.join("box.toml"))
        .args(["--", "-c"])
        .arg(format!(
            "zsh -lc \"box-egress-probe move-authority-parent '{}' '{}' box.toml\"",
            source.display(),
            destination.display()
        ))
        .env("HOME", box_.operator_home())
        .env("PATH", &path)
        .output()
        .expect("run the selected authority configuration");

    assert!(output.status.success(), "{output:?}");
    let seen = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        seen.contains("parent_move=refused"),
        "the contained host binary moved an authority-source parent: {output:?}"
    );
    #[cfg(target_os = "linux")]
    assert!(
        seen.contains(&format!("parent_move_errno={}", libc::EBUSY)),
        "renameat must reach the protected mountpoint: {output:?}"
    );
    // The directory holding the loaded sources is subtracted from the wider grant, so a write
    // beside them is refused as well as one over them.
    assert!(seen.contains("sibling_mutation=refused"), "{output:?}");
    assert!(seen.contains("source_write=refused"), "{output:?}");
    assert_eq!(
        std::fs::read(source.join("box.toml")).expect("config"),
        config_before
    );
    assert_eq!(
        std::fs::read(source.join("policy.dw")).expect("policy"),
        policy_before
    );
    assert!(!destination.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn nested_authority_parents_are_protected_through_each_writable_spelling() {
    use containment::{ContainmentConfig, Operation, Scope};
    use sha2::{Digest as _, Sha256};

    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let probe = std::path::Path::new(env!("CARGO_BIN_EXE_box-egress-probe"));
    let trampoline = probe
        .parent()
        .expect("probe directory")
        .join("strands-box-contain-trampoline");
    for spelling in ["source", "alias"] {
        for parent in ["outer", "outer/inner"] {
            let directory = fixture::short_temporary_home();
            let root = directory.path().canonicalize().expect("fixture root");
            let source = root.join("source");
            let alias = root.join("alias");
            let authority = source.join("outer/inner/policy.dw");
            std::fs::create_dir_all(authority.parent().expect("authority parent"))
                .expect("authority directories");
            std::fs::write(&authority, "authority").expect("authority file");
            std::os::unix::fs::symlink(&source, &alias).expect("writable alias");
            let opened = std::fs::File::open(&authority).expect("open authority");
            let config = ContainmentConfig::new()
                .allow(probe, Operation::Exec, Scope::File)
                .expect("probe grant")
                .allow(&alias, Operation::Write, Scope::Root)
                .expect("writable root through alias")
                .protect_write(&authority, &opened)
                .expect("authority protection");
            let config_json = config.to_json().expect("containment config");
            let config_file = root.join("containment.json");
            std::fs::write(&config_file, &config_json).expect("write containment config");
            let moved_parent = root.join(spelling).join(parent);
            let destination = moved_parent.with_extension("moved");
            let relative_authority = if parent == "outer" {
                "inner/policy.dw"
            } else {
                "policy.dw"
            };
            let control_source = root.join("control");
            let control_authority = control_source.join(relative_authority);
            std::fs::create_dir_all(control_authority.parent().expect("control parent"))
                .expect("control directories");
            std::fs::write(&control_authority, "authority").expect("control authority");
            let control = std::process::Command::new(probe)
                .arg("move-authority-parent")
                .arg(&control_source)
                .arg(root.join("control-moved"))
                .arg(relative_authority)
                .output()
                .expect("uncontained parent movement");
            assert!(control.status.success(), "{control:?}");
            for expected in [
                "sibling_mutation=allowed",
                "parent_move=allowed",
                "source_replacement=allowed",
            ] {
                assert!(
                    stdout(&control).contains(expected),
                    "{expected}: {control:?}"
                );
            }
            assert_eq!(
                std::fs::read_to_string(&control_authority).expect("control replacement"),
                "replacement"
            );

            let output = std::process::Command::new(&trampoline)
                .arg("--config")
                .arg(&config_file)
                .arg("--config-sha256")
                .arg(
                    Sha256::digest(config_json.as_bytes())
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                )
                .arg("--")
                .arg(probe)
                .arg("move-authority-parent")
                .arg(&moved_parent)
                .arg(&destination)
                .arg(relative_authority)
                .output()
                .expect("contained parent movement");
            assert!(output.status.success(), "{spelling}/{parent}: {output:?}");
            let seen = stdout(&output);
            for expected in [
                "sibling_mutation=allowed".to_owned(),
                "parent_move=refused".to_owned(),
                format!("parent_move_errno={}", libc::EBUSY),
                "source_write=refused".to_owned(),
            ] {
                assert!(
                    seen.contains(&expected),
                    "{spelling}/{parent}: {expected}: {output:?}"
                );
            }
            assert_eq!(
                std::fs::read_to_string(&authority).expect("authority"),
                "authority"
            );
            assert!(!destination.exists(), "{spelling}/{parent}");
        }
    }
}

#[test]
fn a_host_binary_cannot_use_the_broker_to_move_an_authority_sources_parent() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let probe = std::path::Path::new(env!("CARGO_BIN_EXE_box-egress-probe"));
    let probe_dir = probe.parent().expect("the probe has a parent directory");
    let path = format!(
        "{}:{}",
        probe_dir.display(),
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())
    );
    const POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "box-egress-probe" };
permit(principal, action == Box::Action::"fs:move", resource);
"#;
    let box_ = Request::with_config("broker-auth-parent", POLICY, PROBE_WRITER_TOOL)
        .env("PATH", &path)
        .expect();
    let source = box_.workspace().join(".strands-box");
    let destination = box_.workspace().join(".strands-box-moved");
    let moved_config = destination.join("box.toml");
    let alias = box_.root().join("bin/zsh");

    let output = box_.bash(&format!(
        "zsh -lc \"box-egress-probe broker-move-authority-parent '{}' '{}' '{}' '{}'\"",
        alias.display(),
        source.display(),
        destination.display(),
        moved_config.display()
    ));

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        !seen.contains("broker_reached=yes"),
        "a host binary reached the broker from its leaf: {output:?}"
    );
    assert!(
        seen.contains("broker_parent_move=refused"),
        "the host binary used the broker to move an authority-source parent: {output:?}"
    );
    assert!(
        seen.contains("moved_write=refused"),
        "the host binary changed the configuration through a moved parent: {output:?}"
    );
    assert!(box_.config().exists());
    assert!(box_.workspace().join(".strands-box/policy.dw").exists());
    assert!(!destination.exists());

    // The agent still reaches the broker, and the broker refuses the same move for it.
    let agent = box_.bash(&format!(
        "zsh -lc \"mv -- '{}' '{}'\"",
        source.display(),
        destination.display()
    ));
    assert!(
        stderr(&agent).contains("strands-shell: mv:"),
        "the agent's move did not reach the broker: {agent:?}"
    );
    assert!(
        box_.config().exists(),
        "the agent moved an authority-source parent through the broker: {agent:?}"
    );
    assert!(box_.workspace().join(".strands-box/policy.dw").exists());
    assert!(!destination.exists(), "{agent:?}");
}

/// A builtin wins over a same-named host binary, so `shell:exec` keeps governing it.
///
/// `echo` is both one of the Shell's own programs and `/bin/echo`. Were the `PATH` walk
/// consulted first, an operator's `shell:exec` rule would silently start describing a host exec —
/// and under `NO_BINARY_POLICY`, which permits no host binary at all, `echo` would break.
#[test]
fn a_builtin_wins_over_a_same_named_host_binary() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(NO_BINARY_POLICY, "spawn-builtin-wins");

    let output = box_.bash(r#"zsh -lc "echo BUILTIN_WON""#);

    assert!(
        stdout(&output).contains("BUILTIN_WON"),
        "`echo` must resolve to the Shell's own program, which shell:exec permits: {output:?}"
    );
    assert!(output.status.success(), "{output:?}");
}

/// A loaded authority source is immutable and unreadable through an interpreter, and the protection
/// is by identity: the `box.toml` and `policy.dw` this run loaded cannot be opened or changed,
/// wherever they sit.
#[test]
fn a_loaded_authority_source_is_immutable_and_unreadable() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_under(PERMISSIVE_POLICY, "shell-authority-floor");
    let config = box_.config();
    let policy = config
        .parent()
        .expect("the config has a parent")
        .join("policy.dw");
    let config = config.display().to_string();
    let policy = policy.display().to_string();

    let output = box_.bash(&format!(
        r#"zsh -lc 'cat {config}' 2>&1 || printf 'config unreadable\n'
           zsh -lc 'printf changed > {config}' 2>&1 || printf 'config immutable\n'
           zsh -lc 'cat {policy}' 2>&1 || printf 'policy unreadable\n'
           zsh -lc 'printf changed > {policy}' 2>&1 || printf 'policy immutable\n'"#
    ));

    let seen = format!("{}{}", stdout(&output), stderr(&output));
    for expected in [
        "config unreadable",
        "config immutable",
        "policy unreadable",
        "policy immutable",
    ] {
        assert!(seen.contains(expected), "{expected}: {output:?}");
    }
    // The refusal names the loaded authority source itself, so the protection is by identity.
    assert!(
        seen.contains("authority source that this run loaded"),
        "a loaded source must be refused by its identity: {output:?}"
    );
    // The config bytes on the host are unchanged.
    assert!(
        std::fs::read_to_string(box_.config())
            .expect("the config still reads on the host")
            .contains("[agent]"),
        "the config bytes were changed: {output:?}"
    );
}
