//! The contained filesystem boundary, asserted by running a real workload.
//!
//! These tests exercise what the kernel enforces, not what the rendered profile
//! says. The profile-text assertions live in `containment`'s conformance suite;
//! here a workload actually runs under Seatbelt and its reads and writes either
//! land or are denied.
//!
//! Every test drives the shipped `strands-box` binary end to end, so a failure
//! means the boundary moved — not that a fixture drifted.
//!
//! **Each test configures a box, then runs in it.** The policy is supplied once, in the
//! configuration; the runs carry no authority at all. That is what makes these tests assertions
//! about a *stored* boundary rather than about one assembled from the arguments of the same
//! command being measured.
//!
//! The fixture declares an agent home under the operator home, granted read and write, with
//! `TMPDIR` inside it. `HOME` is the operator's own home unless `[agent] env.HOME` says otherwise,
//! and reach under either is exactly what `[agent.filesystem]` lists.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "support/fixture.rs"]
mod fixture;

use fixture::{Configured, Request};

/// A workload may run any Shell command and reach any file the profile allows.
///
/// Authorization is not what these tests measure — the Seatbelt boundary is — so
/// policy permits every action and the profile does the confining.
const PERMIT_EVERY_EFFECT: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource);
"#;

/// Configure a box that permits every effect, and hand back the running box.
fn box_permitting_everything(name: &str) -> Configured {
    Request::with_policy(name, PERMIT_EVERY_EFFECT).expect()
}

/// Run `script` in `box_`, prefixed with the readiness marker [`assert_ran`] looks
/// for.
///
/// Every script prints `READY` before doing anything, so a test asserting *denial*
/// cannot also pass when the workload failed to exec at all.
fn probe(box_: &Configured, script: &str) -> Output {
    box_.bash(&format!("printf 'READY\\n'; {script}"))
}

/// The workload's output with the readiness marker stripped.
fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .strip_prefix("READY")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Assert the contained workload actually started.
///
/// Without this, a test asserting *denial* also passes when the workload failed to
/// exec at all — which proves nothing about the filesystem boundary. Every negative
/// test below calls this before checking what was refused.
fn assert_ran(output: &Output) {
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("READY"),
        "the workload never started, so this test proves nothing: {output:?}"
    );
}

/// The whole standard output of a run that prints no readiness marker.
fn raw_stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// The whole standard error of a run.
fn raw_stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn a_workload_writes_at_any_depth_under_its_home() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    // The home is one blanket grant, not three named subtrees, so state does not
    // have to live in .codex, .claude, or .kiro to be writable.
    let box_ = box_permitting_everything("depth");

    // Only bash builtins are available: the profile permits exec on exactly the
    // literals the box granted, so there is no `mkdir` or `cat` to call.
    let output = probe(
        &box_,
        "d=\"$HOME/some/agent/state\"; p=\"\"; \
         for part in ${d//\\// }; do p=\"$p/$part\"; [[ -d $p ]] || \
           { printf x > \"$p\" 2>/dev/null; } ; done; \
         printf accumulated > \"{box_home}/state-value\" \
         && { read -r v < \"{box_home}/state-value\"; printf '%s' \"$v\"; }",
    );

    assert_ran(&output);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(stdout(&output), "accumulated");
    assert_eq!(
        std::fs::read_to_string(box_.box_home().join("state-value")).unwrap(),
        "accumulated",
        "the write reached the box home on the host"
    );
}

#[test]
fn a_workload_writes_to_its_temporary_directory() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    // The fixture declares TMPDIR under its agent home and grants that tree.
    let box_ = box_permitting_everything("tmpdir");

    let output = probe(
        &box_,
        "printf scratch > \"$TMPDIR/probe\" \
         && { read -r v < \"$TMPDIR/probe\"; printf '%s' \"$v\"; }",
    );

    assert_ran(&output);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(stdout(&output), "scratch");
    assert_eq!(
        std::fs::read_to_string(box_.box_home().join(".tmp/probe")).unwrap(),
        "scratch",
        "TMPDIR resolves to .tmp/ inside the declared agent home"
    );
}

#[test]
fn the_workload_identity_is_fixed_rather_than_inherited() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_permitting_everything("identity");

    let output = probe(
        &box_,
        "printf '%s\\n%s\\n%s\\n' \"$USER\" \"$PWD\" \"$PATH\"",
    );

    assert!(output.status.success(), "{output:?}");
    let printed = stdout(&output);
    let lines: Vec<&str> = printed.lines().collect();
    assert_eq!(lines[0], "strands-box", "USER is fixed, not the operator's");
    // **`PWD` is the workspace, not the box home.** It was the box home until `AccessMode::Traverse`
    // existed: the workload could not enter a directory its profile did not grant, and granting the
    // workspace `Read` would have let its own syscalls read it. A traverse grant makes the path
    // present and empty, so the agent stands there and reads nothing.
    assert_eq!(
        Path::new(lines[1]),
        box_.workspace(),
        "the working directory is the workspace"
    );
    assert_ne!(
        Path::new(lines[1]),
        box_.box_home(),
        "the workspace is not the box home; if these are equal the traverse grant did not apply"
    );
    // **`PATH` is the alias directory, then the declared search path.** Nothing is declared here,
    // so the operator's own `PATH` follows the aliases, and the aliases come first so `zsh` and
    // `python3` resolve to the box's own.
    let alias_directory = box_.root().join("bin");
    assert!(
        lines[2].starts_with(&format!("{}:", alias_directory.display())),
        "PATH must start with the alias directory: {}",
        lines[2]
    );
}

/// **Reach under the operator's home is exactly what `[agent.filesystem]` lists.** A listed file
/// reads; an unlisted sibling, and an unlisted harness directory, do not.
///
/// This is the mirror image of the pins it replaces: `HOME` is no longer a private box home, and the
/// operator's home is no longer absent to the workload. What bounds the agent is the list.
#[test]
fn reach_under_the_operator_home_is_only_what_is_listed() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let request = Request::with_policy("operator-home", PERMIT_EVERY_EFFECT);
    let listed = request.operator_home().join("notes");
    std::fs::create_dir(&listed).expect("a listed tree");
    std::fs::write(listed.join("api.md"), "listed contents\n").expect("a listed file");
    let secret = request.operator_home().join("operator-secret");
    std::fs::write(&secret, "operator only\n").expect("write operator secret");
    let codex = request.operator_home().join(".codex");
    std::fs::create_dir(&codex).expect("operator .codex");
    std::fs::write(codex.join("auth.json"), "{\"token\":\"real\"}\n").expect("operator token");
    let box_ = request.agent_read(&[listed.as_path()]).expect();

    let output = probe(
        &box_,
        &format!(
            "read -r v < {} && printf 'LISTED=%s\\n' \"$v\"; \
             read -r v < {} 2>/dev/null && printf 'SIBLING=%s\\n' \"$v\"; \
             read -r v < {} 2>/dev/null && printf 'HARNESS=%s\\n' \"$v\"; printf done",
            shell_quote(&listed.join("api.md")),
            shell_quote(&secret),
            shell_quote(&codex.join("auth.json"))
        ),
    );

    assert_ran(&output);
    let seen = stdout(&output);
    assert!(
        seen.contains("LISTED=listed contents"),
        "a listed file under the operator home must read: {output:?}"
    );
    assert!(
        !seen.contains("SIBLING=") && !seen.contains("operator only"),
        "an unlisted sibling must not reach the workload: {output:?}"
    );
    assert!(
        !seen.contains("HARNESS=") && !seen.contains("real"),
        "an unlisted harness directory must not reach the workload: {output:?}"
    );
    assert!(seen.contains("done"), "{output:?}");
}

/// **`HOME` is the operator's home when `env.HOME` is unset, and the declared value when set.**
#[test]
fn home_is_the_operators_unless_the_agent_declares_one() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let declared = box_permitting_everything("home-declared");
    let output = probe(&declared, "printf '%s' \"$HOME\"");
    assert_ran(&output);
    assert_eq!(
        Path::new(&stdout(&output)),
        declared.box_home(),
        "a declared `env.HOME` is what the agent reads"
    );

    let undeclared = Request::with_policy("home-operator", PERMIT_EVERY_EFFECT)
        .without_agent_home()
        .expect();
    let output = probe(&undeclared, "printf '%s' \"$HOME\"");
    assert_ran(&output);
    assert_eq!(
        Path::new(&stdout(&output)),
        undeclared.operator_home(),
        "with no `env.HOME` the agent's home is the operator's own"
    );
    // And nothing under it is writable, because nothing under it is listed.
    let marker = undeclared.operator_home().join("unlisted-marker");
    let output = probe(
        &undeclared,
        &format!(
            "printf x > {} 2>/dev/null; printf done",
            shell_quote(&marker)
        ),
    );
    assert_ran(&output);
    assert!(
        !marker.exists(),
        "the operator home is HOME and still unwritable where no list names it"
    );
}

/// **No host variable is inherited.** A distinctive host `TERM` does not reach the box, and `LANG`
/// is absent unless declared.
#[test]
fn no_host_variable_is_inherited() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("no-inheritance", PERMIT_EVERY_EFFECT)
        .env("TERM", "xterm-unusual-for-this-test")
        .env("LANG", "xx_YY.UTF-8")
        .agent_env("LC_ALL", "C.declared")
        .expect();

    let output = probe(
        &box_,
        "printf 'TERM=%s LANG=%s LC_ALL=%s' \"${TERM-unset}\" \"${LANG-unset}\" \"${LC_ALL-unset}\"",
    );

    assert_ran(&output);
    let seen = stdout(&output);
    assert!(
        !seen.contains("xterm-unusual-for-this-test"),
        "the host's TERM must not reach the agent: {output:?}"
    );
    assert!(
        seen.contains("LANG=unset LC_ALL=C.declared"),
        "a host variable reaches the agent only through `[agent] env`: {output:?}"
    );
}

/// **The startup disclosure names every direct grant, the runtime minimum, and the effective `HOME`
/// and `PATH`.**
#[test]
fn the_startup_disclosure_names_every_grant_and_the_home_and_path() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let request = Request::with_policy("disclosure", PERMIT_EVERY_EFFECT);
    let listed = request.operator_home().join("vendor");
    std::fs::create_dir(&listed).expect("a listed tree");
    let box_ = request.agent_read(&[listed.as_path()]).expect();

    let output = probe(&box_, "printf ok");
    assert_ran(&output);
    let reported = raw_stderr(&output);
    for needle in [
        "strands-box: [agent] runs",
        "no policy decision over these paths",
        &format!("read        {}", box_.box_home().display()),
        &format!("write       {}", box_.box_home().display()),
        &format!("read        {}", listed.display()),
        "strands-box: [agent] runtime minimum, added by Core:",
        "/dev/null",
        &format!("HOME={}", box_.box_home().display()),
        &format!("PATH={}:", box_.root().join("bin").display()),
    ] {
        assert!(
            reported.contains(needle),
            "the disclosure must carry {needle:?}: {reported}"
        );
    }
}

/// The box's own private tree is unreachable, including the stored policy.
///
/// This is the reachability-class split the layout is organized around, checked from
/// inside the boundary rather than from the path arithmetic: `private/` holds the
/// record, the policy text, the containment configs, and the control socket, and no
/// profile placeholder names any of it. A workload that could read `policy.dw` would
/// know exactly which requests to shape, and one that could reach `control.sock`
/// would hold the credential the design exists to keep from it.
#[test]
fn the_boxs_own_private_tree_is_unreachable_from_inside() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_permitting_everything("private-tree");
    let private = box_.root().join("private");
    assert!(
        private.join("policy.dw").is_file(),
        "the stored policy must exist for its unreachability to mean anything"
    );

    let output = probe(
        &box_,
        &format!(
            "read -r v < {} 2>/dev/null && printf 'leaked:%s' \"$v\" || printf policy-denied; \
             [[ -e {} ]] && printf ' control-visible' || printf ' control-denied'",
            shell_quote(&private.join("policy.dw")),
            shell_quote(&private.join("live").join("control.sock")),
        ),
    );

    assert_ran(&output);
    let printed = stdout(&output);
    assert!(
        printed.contains("policy-denied") && !printed.contains("permit("),
        "the workload must not be able to read the policy governing it: {output:?}"
    );
    assert!(
        printed.contains("control-denied"),
        "the control socket must be unreachable: {output:?}"
    );
}

#[test]
fn state_written_in_one_run_is_readable_by_the_next() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    // **A box's home persists from the first run until `rm`, so an agent's own state survives.**
    // That is what makes one sign-in per box a prompt rather than a prompt every run.
    //
    // The path is directly in `$HOME`, which is this box's own home. A draft wrote to
    // `$HOME/.codex/` and relied on the operator's harness directory being kernel-granted; that
    // grant is gone with the shared home, and the property under test never depended on it.
    let box_ = box_permitting_everything("persist");

    let first = probe(&box_, "printf logged-in > \"$HOME/.session-token\"");
    assert_ran(&first);
    assert!(first.status.success(), "{first:?}");

    let second = probe(
        &box_,
        "read -r v < \"$HOME/.session-token\"; printf '%s' \"$v\"",
    );
    assert_ran(&second);
    assert!(second.status.success(), "{second:?}");
    assert_eq!(stdout(&second), "logged-in");

    // The operator home root is not writable. The workload reaches none of it with its own syscalls.
    let outside_path = box_.operator_home().join("outside-a-granted-directory");
    let outside = probe(
        &box_,
        &format!(
            "printf leaked > {} 2>/dev/null; printf done",
            shell_quote(&outside_path)
        ),
    );
    assert_ran(&outside);
    assert!(
        !outside_path.exists(),
        "the operator home root must not be writable by the agent's own syscalls"
    );
}
/// **A second run reuses the box rather than recreating it, and does not clobber its home.**
///
/// This test used to assert that a second `create` for one name refused. There is no `create`
/// verb now: a box is created by `run` in a workspace, and a later `run` reuses it. So the property
/// that survives is that reuse is not a re-create — the box's accumulated home state is left
/// exactly as it was. `box_project.rs::a_second_run_reuses_the_box` covers reuse succeeding; this
/// covers that it touches nothing.
#[test]
fn a_second_run_reuses_the_box_and_leaves_its_home_untouched() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_permitting_everything("recreate");
    let first = probe(&box_, "printf logged-in > \"{box_home}/.session-token\"");
    assert_ran(&first);
    assert!(first.status.success(), "{first:?}");

    // A second run of the same box: reuse, not re-create. It must succeed and touch nothing.
    let again = box_.run(&[fixture::no_op_program()]);
    assert!(
        again.status.success(),
        "a second run must reuse the box, not fail: {}",
        String::from_utf8_lossy(&again.stderr)
    );

    let after = probe(
        &box_,
        "read -r v < \"{box_home}/.session-token\"; printf '%s' \"$v\"",
    );
    assert_ran(&after);
    assert_eq!(
        stdout(&after),
        "logged-in",
        "reuse must leave the box home's accumulated state untouched"
    );
}
/// A box that was never created cannot be run.
///
/// The structural half of "a run cannot bring a box into existence": `run` only ever
/// opens. A misspelled `--name` is a refusal naming the fix, rather than a silently
/// fresh default-deny box whose first request fails with a denial that reads like a
/// policy bug.
#[test]
fn running_an_uncreated_box_is_refused() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_permitting_everything("configured");

    let output = std::process::Command::new(fixture::box_binary())
        .arg("run")
        .arg("--config")
        .arg(box_.operator_home().join("missing.toml"))
        .arg("--")
        .arg("/bin/bash")
        .arg("-c")
        .arg("printf ran")
        .env("HOME", box_.operator_home())
        .output()
        .expect("spawn strands-box run");

    assert!(
        !output.status.success(),
        "an unconfigured box must not run a workload: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing.toml") && stderr.contains("No such file"),
        "the refusal must name the missing explicit configuration: {stderr}"
    );
    assert!(
        !output.stdout.starts_with(b"ran"),
        "the workload must not have run: {output:?}"
    );
}

/// Two boxes do not share the directory each one writes.
///
/// **`$HOME` is the box home.** Each box receives a different read-write directory, so one box
/// cannot read another box's marker.
///
/// This test used to write to `$HOME` and pass, for a reason that had nothing to do with the
/// property: the fixture home sat under `/tmp`, the Linux view mounts a fresh writable tmpfs there,
/// and each box got its own. So the write succeeded and the second box saw nothing — the right
/// answer from the wrong mechanism. Moving the fixture home to `/var/tmp` made the write fail, which
/// is what surfaced it.
#[test]
fn distinct_names_do_not_share_state() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let first = box_permitting_everything("first");
    let output = probe(&first, "printf one > \"$BOX_HOME/marker\"");
    assert_ran(&output);
    assert!(output.status.success(), "{output:?}");

    let second = box_permitting_everything("second");
    let output = probe(
        &second,
        "read -r v < \"$BOX_HOME/marker\" 2>/dev/null && printf '%s' \"$v\" || printf absent",
    );

    assert_ran(&output);
    assert_eq!(
        stdout(&output),
        "absent",
        "a differently named box starts with its own home"
    );
}

/// An open question, **not** resolved by this test.
///
/// The question is whether a workload holding `file-write-create` on all of its
/// home can `link(2)` a host file into that home and read it through a path
/// the profile allows — turning a write grant into a read channel.
///
/// This test cannot answer it. The profile permits exec on exactly the literals the
/// box granted, so there is no `ln` to run and bash has no link builtin: the workload
/// cannot reach `link(2)` at all through the surface it is given. That is a real
/// property worth pinning — the reachable attack surface excludes link creation — but
/// it is weaker than the claim that the syscall is denied.
///
/// Answering it properly needs a purpose-built probe binary granted as the exec
/// literal, calling `link(2)` directly. Until that exists the question
/// stays open; do not read this test as having closed it.
#[test]
fn the_workload_cannot_reach_link_creation_through_its_exec_surface() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_permitting_everything("forge");
    let secret = box_.operator_home().join("link-target");
    std::fs::write(&secret, "host only").expect("write link target");

    let output = probe(
        &box_,
        &format!(
            "type -t ln || printf no-ln; \
             read -r w < {} 2>/dev/null && printf ' leaked:%s' \"$w\" || printf ' source-denied'",
            shell_quote(&secret)
        ),
    );

    assert_ran(&output);
    let printed = stdout(&output);
    assert!(
        printed.contains("no-ln"),
        "the workload must have no `ln` to invoke: {output:?}"
    );
    assert!(
        printed.contains("source-denied"),
        "the link source must be unreadable in the first place: {output:?}"
    );
    assert!(
        !printed.contains("host only"),
        "the host file's contents must not reach the workload: {output:?}"
    );
}

/// Quote a path for `bash`. Fixture paths are under `/tmp`, so they contain no
/// single quotes; reject one rather than emit a broken command.
fn shell_quote(path: &Path) -> String {
    let path = path.to_str().expect("fixture path is UTF-8");
    assert!(
        !path.contains('\''),
        "fixture paths must not contain a single quote: {path}"
    );
    format!("'{path}'")
}

/// **A harness configuration directory reads and writes when it is listed, and not otherwise.**
///
/// Core holds no harness opinion: the denial of `~/.claude` and its siblings left the box, and an
/// operator who wants Claude Code to find its configuration lists the directory. The write half is
/// the sharper one, so both directions are asserted on the listed directory and the unlisted one.
#[test]
fn a_harness_configuration_directory_reads_when_listed_and_not_otherwise() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let request = Request::with_policy("harness-listed", PERMIT_EVERY_EFFECT);
    for (directory, file) in [(".claude", "settings.json"), (".codex", "auth.json")] {
        let planted = request.operator_home().join(directory);
        std::fs::create_dir_all(&planted).expect("a harness directory the operator already has");
        std::fs::write(planted.join(file), "OPERATOR_CONTENTS\n").expect("its contents");
    }
    let claude = request.operator_home().join(".claude");
    let codex = request.operator_home().join(".codex");
    let box_ = request
        .agent_read(&[claude.as_path()])
        .agent_write(&[claude.as_path()])
        .expect();

    let output = probe(
        &box_,
        &format!(
            "read -r v < {claude}/settings.json && printf 'LISTED_READ=%s\\n' \"$v\"; \
             printf hooked > {claude}/hooks.json 2>/dev/null && printf 'LISTED_WROTE\\n'; \
             read -r v < {codex}/auth.json 2>/dev/null && printf 'UNLISTED_READ=%s\\n' \"$v\"; \
             printf hooked > {codex}/config.toml 2>/dev/null && printf 'UNLISTED_WROTE\\n'; \
             printf done",
            claude = shell_quote(&claude),
            codex = shell_quote(&codex)
        ),
    );

    assert_ran(&output);
    let seen = stdout(&output);
    assert!(
        seen.contains("LISTED_READ=OPERATOR_CONTENTS") && seen.contains("LISTED_WROTE"),
        "a listed harness directory must read and write: {output:?}"
    );
    assert!(
        !seen.contains("UNLISTED_READ") && !seen.contains("UNLISTED_WROTE"),
        "an unlisted harness directory must stay unreachable: {output:?}"
    );
    assert!(
        claude.join("hooks.json").is_file(),
        "the listed write must land on the host"
    );
    assert!(
        !codex.join("config.toml").exists(),
        "the unlisted write must not land on the host"
    );
    assert!(seen.contains("done"), "{output:?}");
}

/// **Every box reaches the runtime minimum Core adds.**
///
/// A read is asserted rather than a `test -r`, because the namespace launcher answers `ENOENT` for
/// a path outside the view, and only bytes prove the path is in it.
#[test]
fn a_box_reaches_the_runtime_minimum() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let box_ = box_permitting_everything("floor");
    let script = "read -r -n 4 tz < /etc/localtime 2>/dev/null && printf 'LOCALTIME=%s ' \"$tz\"; \
                  { : < /dev/null; } 2>/dev/null && printf 'NULL_OPENED '; \
                  { : > /dev/null; } 2>/dev/null && printf 'NULL_WRITTEN '; \
                  printf DONE";
    let expected = "LOCALTIME=TZif NULL_OPENED NULL_WRITTEN DONE";

    let listed = probe(&box_, script);
    assert_ran(&listed);
    assert_eq!(
        stdout(&listed),
        expected,
        "a box must read the runtime minimum: {listed:?}"
    );
}

/// **The workspace is enterable, and unreadable until a list names it.**
///
/// The working directory *is* the workspace, so the positive half proves nothing on its own, and
/// both denials are asserted here. Linux mounts an empty read-only `tmpfs` at the path: the name
/// resolves, a read answers `ENOENT`, and a write answers `EROFS`. macOS renders
/// `file-read-metadata` on the literal and its ancestors and no `file-read*`.
///
/// The file planted below is what makes the read assertion mean something: an `ENOENT` for a file
/// that was never there would pass against any implementation at all.
#[test]
fn the_workspace_is_enterable_and_unreadable_until_listed() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_permitting_everything("traverse-workspace");

    // Planted from the HOST, so the file genuinely exists at that path. The agent must still not
    // see it.
    let planted = box_.workspace().join("planted.txt");
    std::fs::write(&planted, "PROJECT_CONTENTS\n").expect("a real file in the workspace");
    std::fs::create_dir_all(box_.workspace().join("subdir")).expect("a real directory in it");

    let output = probe(
        &box_,
        "printf 'cwd=%s\\n' \"$PWD\"\n\
         read -r leaked < ./planted.txt 2>/dev/null && printf 'READ_LEAKED=%s\\n' \"$leaked\"\n\
         printf y > ./written.txt 2>/dev/null && printf 'WRITE_LEAKED\\n'\n\
         printf y > ./subdir/written.txt 2>/dev/null && printf 'NESTED_WRITE_LEAKED\\n'\n\
         set -- ./*\n\
         printf 'GLOB=%s\\n' \"$1\"\n\
         printf 'done\\n'",
    );
    assert_ran(&output);
    let seen = stdout(&output);

    // The positive half: the agent really is standing in the workspace.
    assert!(
        seen.contains(&format!("cwd={}", box_.workspace().display())),
        "the workload's working directory must be the workspace: {output:?}"
    );
    // Entry only: the glob stays unexpanded, because the workspace is not enumerable either.
    assert!(
        seen.contains("GLOB=./*"),
        "the agent must not enumerate a workspace no list names: {output:?}"
    );

    // The two denials, which are why `Traverse` exists rather than `Read`.
    assert!(
        !seen.contains("READ_LEAKED"),
        "the agent's own syscalls must not read a workspace no list names: {output:?}"
    );
    assert!(
        !seen.contains("PROJECT_CONTENTS"),
        "the planted file's contents must not appear anywhere: {output:?}"
    );
    assert!(
        !seen.contains("WRITE_LEAKED") && !seen.contains("NESTED_WRITE_LEAKED"),
        "the agent must not write into the workspace it is standing in; a writable directory here \
         would be a place to stage a file at a path the operator's policy names: {output:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&planted).expect("the planted file survives"),
        "PROJECT_CONTENTS\n",
        "the operator's own file must be unchanged"
    );
    assert!(
        !box_.workspace().join("written.txt").exists(),
        "nothing the agent attempted may appear in the operator's workspace"
    );

    // **The control, and it is what separates a working grant from a missing one.** An empty mount
    // and *no* mount look identical to the assertions above — both refuse. The Shell reaches the
    // same file through policy, so a passing read here proves the workspace is genuinely present and
    // readable to the interpreter while absent to the agent.
    let through_shell = probe(&box_, "zsh -lc 'cat ./planted.txt'");
    assert_ran(&through_shell);
    assert!(
        stdout(&through_shell).contains("PROJECT_CONTENTS"),
        "the Shell must read the workspace, or this test would pass with no workspace grant at all: \
         {through_shell:?}"
    );
}

/// **The workload must be able to READ its own trust bundle, with its own syscalls.**
///
/// TLS is the reason. Every runtime the box composes an environment for is pointed at the proxy's CA
/// through `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, or `CODEX_CA_CERTIFICATE`, and it opens that path
/// itself — no interpreter is involved, so no `fs:*` rule can grant it. A grant that presents the
/// path as anything other than a readable file breaks every HTTPS request the box exists to mediate.
///
/// **This is a regression test for a shipped defect.** The CA was granted `AccessMode::Traverse`
/// instead of `Read`, so the Linux backend planned a fresh empty `tmpfs` at the path and the
/// workload saw a *directory*. Codex reported `Is a directory (os error 21)`, every request failed,
/// and it fell back to a host the policy does not permit — three symptoms, none of them naming the
/// grant. Neither shipped example caught it, because both only run `--version`.
///
/// Asserted end to end rather than on the plan, because the plan was *correct*: it faithfully
/// carried out a wrong grant. The mistake was one crate up, so only a test that reads the file
/// through the finished view can see it.
#[test]
fn the_agent_reads_its_own_trust_bundle() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_permitting_everything("trust-readable");

    // Every variable the box sets for a CA, so a rename on either side fails this rather than
    // silently testing nothing.
    let output = probe(
        &box_,
        r#"for name in SSL_CERT_FILE NODE_EXTRA_CA_CERTS CODEX_CA_CERTIFICATE; do
  eval "path=\$$name"
  [ -n "$path" ] || { printf 'UNSET=%s\n' "$name"; continue; }
  [ -d "$path" ] && printf 'DIRECTORY=%s\n' "$name"
  read -r first < "$path" 2>/dev/null && printf 'READ=%s first=%s\n' "$name" "$first"
done
printf 'done\n'"#,
    );
    assert_ran(&output);
    let seen = stdout(&output);

    assert!(
        !seen.contains("UNSET="),
        "every CA variable must name a path, or a runtime reading that one finds nothing: {output:?}"
    );
    assert!(
        !seen.contains("DIRECTORY="),
        "the trust bundle must be a FILE in the view; a directory is what an `AccessMode::Traverse` \
         grant produces, and it breaks TLS for every runtime: {output:?}"
    );
    assert!(
        seen.matches("READ=").count() == 3,
        "all three variables must name a readable file: {output:?}"
    );
    assert!(
        seen.contains("BEGIN CERTIFICATE"),
        "the bundle the workload reads must be the certificate itself, not an empty file the mount \
         happened to create: {output:?}"
    );
}

/// **A credential store beneath a grant is refused, and a store named exactly is a disclosed
/// punch-through.**
///
/// The floor is `containment`'s, judged beneath every grant with the operator home as an anchor; a
/// grant enclosing `~/.aws` is refused by name. Naming the store itself is the one way through, and
/// the box announces it before the workload starts.
#[test]
fn a_credential_store_is_refused_beneath_a_grant_and_disclosed_when_named_exactly() {
    let request = Request::with_policy("read-credential", PERMIT_EVERY_EFFECT);
    let home = request.operator_home().to_path_buf();
    let credentials = home.join(".aws");
    std::fs::create_dir_all(&credentials).expect("a credential store in the fixture home");
    std::fs::write(credentials.join("credentials"), "[default]\n").expect("a credential");

    let (_box, output) = request.agent_read(&[home.as_path()]).attempt();
    assert!(
        !output.status.success(),
        "a grant enclosing a credential store must refuse the run: {}",
        raw_stdout(&output)
    );
    let reported = format!("{}{}", raw_stdout(&output), raw_stderr(&output));
    assert!(
        reported.contains("credential"),
        "the refusal must name what it protects rather than only the path: {reported}"
    );

    // The second half runs the workload, so it needs a launcher; the refusal above does not.
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: the exact-path half needs a containment backend this platform lacks");
        return;
    }
    let request = Request::with_policy("read-credential-exact", PERMIT_EVERY_EFFECT);
    let credentials = request.operator_home().join(".aws");
    std::fs::create_dir_all(&credentials).expect("a credential store in the fixture home");
    let (_box, output) = request.agent_read(&[credentials.as_path()]).attempt();
    let reported = raw_stderr(&output);
    assert!(
        output.status.success(),
        "a store named exactly is the operator's explicit choice: {reported}"
    );
    assert!(
        reported.contains("[agent]: exposes") && reported.contains(".aws (read)"),
        "the punch-through must be announced before the workload starts: {reported}"
    );
}

struct PrivateStateFixture {
    _root: tempfile::TempDir,
    operator_home: PathBuf,
    box_directory: PathBuf,
    workspace: PathBuf,
}

impl PrivateStateFixture {
    fn new(state: &str) -> Self {
        let root = fixture::short_temporary_home();
        let canonical = root.path().canonicalize().expect("the fixture resolves");
        let operator_home = canonical.join("operator");
        let box_directory = canonical.join(state);
        let workspace = canonical.join("workspace");
        for directory in [&operator_home, &box_directory, &workspace] {
            std::fs::create_dir_all(directory).expect("a fixture directory");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&box_directory, std::fs::Permissions::from_mode(0o700))
                .expect("a private box directory");
        }
        Self {
            _root: root,
            operator_home,
            box_directory,
            workspace,
        }
    }

    fn run(&self, read: Option<&Path>, readable: &Path) -> Output {
        let config = self.workspace.join("control.toml");
        let read = read
            .map(|path| {
                format!(
                    "[agent.filesystem]\nread = [{:?}]\n",
                    path.display().to_string()
                )
            })
            .unwrap_or_default();
        std::fs::write(
            &config,
            format!(
                "name = \"private-state\"\nbox_dir = {:?}\n[agent]\ncommand = [\"/bin/bash\"]\n\
                 workspace = {:?}\n{read}",
                self.box_directory.display().to_string(),
                self.workspace.display().to_string(),
            ),
        )
        .expect("the configuration");
        Command::new(fixture::box_binary())
            .arg("run")
            .arg("--config")
            .arg(&config)
            .args([
                "--",
                "-c",
                "if IFS= read -r line < \"$1\"; then printf 'READ:%s\\n' \"$line\"; \
                 else printf 'DENIED\\n'; fi",
                "probe",
            ])
            .arg(readable)
            .env("HOME", &self.operator_home)
            .current_dir(&self.workspace)
            .output()
            .expect("the box starts")
    }

    fn private_record(&self) -> PathBuf {
        self.box_directory.join("private/box.toml")
    }

    fn assert_refused(&self, read: Option<&Path>) {
        assert_private_state_refusal(self.run(read, &self.private_record()));
    }
}

fn assert_private_state_refusal(output: Output) {
    let reported = format!("{}{}", raw_stdout(&output), raw_stderr(&output));
    assert!(
        !output.status.success(),
        "the grant must not expose private Box state: {reported}"
    );
    assert!(
        !raw_stdout(&output).contains("READ:"),
        "the workload read private Box state: {reported}"
    );
    assert!(
        raw_stderr(&output).contains("private Box state"),
        "the refusal must name the private state: {reported}"
    );
}

#[test]
fn an_agent_read_entry_cannot_read_private_state() {
    let fixture = PrivateStateFixture::new("runtime/state");
    let private = fixture.box_directory.join("private");
    assert!(!private.exists(), "this must test first use");
    fixture.assert_refused(Some(&private));
}

#[test]
fn an_agent_read_descendant_cannot_read_private_state() {
    let fixture = PrivateStateFixture::new("runtime/state");
    let record = fixture.private_record();
    assert_private_state_refusal(fixture.run(Some(&record), &record));
}

#[test]
fn an_agent_read_ancestor_cannot_read_private_state() {
    let fixture = PrivateStateFixture::new("runtime/state");
    fixture.assert_refused(fixture.box_directory.parent());
}

#[cfg(unix)]
#[test]
fn a_symlinked_agent_read_entry_cannot_read_private_state() {
    for private in [true, false] {
        let fixture = PrivateStateFixture::new("runtime/state");
        let target = if private {
            fixture.box_directory.join("private")
        } else {
            fixture
                .box_directory
                .parent()
                .expect("a parent")
                .to_path_buf()
        };
        let link = fixture.workspace.join("code");
        std::os::unix::fs::symlink(target, &link).expect("the read-entry symlink");
        // A symlinked entry is refused by name before any grant renders, so the link cannot
        // launder private Box state into a grant.
        let output = fixture.run(Some(&link), &fixture.private_record());
        let reported = format!("{}{}", raw_stdout(&output), raw_stderr(&output));
        assert!(
            !output.status.success(),
            "the grant must not expose private Box state: {reported}"
        );
        assert!(
            !raw_stdout(&output).contains("READ:"),
            "the workload read private Box state: {reported}"
        );
        assert!(
            raw_stderr(&output).contains("symbolic link"),
            "the refusal must name the symlinked entry: {reported}"
        );
    }
}

#[test]
fn a_separate_read_tree_is_readable_while_private_state_is_absent() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let fixture = PrivateStateFixture::new("runtime/state");
    let code = fixture.box_directory.with_file_name("state-code");
    std::fs::create_dir(&code).expect("the read-entry directory");
    let readable = code.join("module.txt");
    std::fs::write(&readable, "code-content\n").expect("the code file");
    let output = fixture.run(Some(&code), &readable);
    assert!(output.status.success(), "{}", raw_stderr(&output));
    assert_eq!(raw_stdout(&output), "READ:code-content\n");

    let output = fixture.run(Some(&code), &fixture.private_record());
    assert!(output.status.success(), "{}", raw_stderr(&output));
    assert_eq!(raw_stdout(&output), "DENIED\n");
}
