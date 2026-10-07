//! The resolved-command vocabulary: `shell:exec` and `shell:spawn`.
//!
//! A command line is judged **once**, on the resolved command. `shell:exec` is the decision
//! when the Shell implements the program; `shell:spawn` is the decision when a host binary
//! would run instead. Both carry the resolved program, its leading arguments, and the working
//! directory — the facts a rule needs and the submitted text cannot supply.
//!
//! An earlier action judged the submitted command *text*, before parsing. It carried `command`
//! and nothing else, because nothing else existed at that point, so a rule could only
//! pattern-match a string. That action is gone, and the name `shell:exec` now belongs to the
//! decision on the resolved command. A rule guarding `context.input.command` therefore still
//! loads; what moved is *when* it is judged, and that is what this file pins.
//!
//! Three properties are pinned here, and the second is the load-bearing one:
//!
//! 1. **A rule discriminates on the resolved program, not on the text.** Six spellings of
//!    one command produce one `program`, so a `forbid` cannot be evaded by quoting, by a
//!    variable, or by an alias.
//! 2. **A grant of `shell:exec` is not a grant of `shell:spawn`.** Both shipped examples carry
//!    an unconditional `permit` on the run action. Had the host-binary case been a *field* on
//!    it instead of its own action, every such policy would have started permitting
//!    host-binary execution the day passthrough shipped, without its author touching a line.
//! 3. **`shell:spawn` is refused unless a rule names it.** Absent policy is default-deny,
//!    and a `permit` written for the programs the Shell implements must not reach a host
//!    binary that escapes `fs:*` admission entirely.

mod support;

use std::path::PathBuf;

use policy::{Decision, GovernedBox, Outcome, Policy, PolicyEngine, Principal, Request};

fn loaded(source: &str) -> PolicyEngine {
    support::open_policy(vec![Policy {
        origin: PathBuf::from("shell-resolved.dw"),
        text: source.to_string(),
    }])
    .expect("policy loads")
}

fn governed() -> GovernedBox {
    GovernedBox::assigned("test-box")
}

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| (*w).to_string()).collect()
}

fn allows(policy: &PolicyEngine, request: &Request<'_>) -> bool {
    matches!(
        policy.decide(&governed(), &Principal::agent(), request),
        Decision::Allow { .. }
    )
}

/// A resolved run of `program` with `words`, from `/workspace`.
fn run<'a>(command: &'a str, program: &'a str, words: &'a [String]) -> Request<'a> {
    Request::ShellExec {
        command,
        program,
        args: words,
        cwd: "/workspace",
    }
}

/// The permit every fixture builds on: commands are allowed, and the rule under test
/// narrows from there.
const PERMIT_RUN: &str = r#"permit (principal, action == Box::Action::"shell:exec", resource);"#;

/// Property 1, the direction that matters: one `forbid` on the resolved program refuses
/// every spelling of it.
///
/// A text rule cannot do this. `command like "*rm *"` misses `\rm`, misses `X=rm; $X`, and
/// *over*-denies `charm --version`, whose text contains `rm `. The submitted text differs
/// in all four cases; the resolved program does not.
#[test]
fn a_forbid_on_the_resolved_program_survives_every_spelling() {
    // `arg1` is optional, so the `has` guard is mandatory — see
    // `reading_an_optional_argument_unguarded_aborts_at_load`.
    let policy = loaded(&format!(
        r#"{PERMIT_RUN}
           forbid (principal, action == Box::Action::"shell:exec", resource)
           when {{
               context.input.program == "rm" &&
               context.input has arg1 && context.input.arg1 == "-rf"
           }};"#
    ));

    let recursive = args(&["-rf", "/workspace/data"]);
    // Four submissions, one resolved program. The Shell resolved each before deciding, so
    // the rule sees `rm` whatever the author of the command line wrote.
    for command in [
        "rm -rf /workspace/data",
        r#""rm" -rf /workspace/data"#,
        r"\rm -rf /workspace/data",
        "X=rm; $X -rf /workspace/data",
    ] {
        assert!(
            !allows(&policy, &run(command, "rm", &recursive)),
            "spelling `{command}` must be refused on its resolved program"
        );
    }

    // The over-denial a text rule commits: `charm --version` contains the substring
    // `rm `, and must be allowed.
    let version = args(&["--version"]);
    assert!(
        allows(&policy, &run("charm --version", "charm", &version)),
        "a program whose NAME contains the forbidden one must not be caught"
    );

    // And the same program without the forbidden argument.
    let single = args(&["/workspace/data"]);
    assert!(
        allows(&policy, &run("rm /workspace/data", "rm", &single)),
        "the rule names an argument, so `rm` alone stays allowed"
    );
}

/// An alias is the sharpest case, because the box has no other defence against it: the
/// `alias` builtin raises no decision of its own, so a rule written on the submitted text
/// is defeated by one line the policy never sees.
#[test]
fn an_alias_cannot_launder_a_forbidden_program() {
    let policy = loaded(&format!(
        r#"{PERMIT_RUN}
           forbid (principal, action == Box::Action::"shell:exec", resource)
           when {{ context.input.program == "rm" }};"#
    ));

    // `alias safe=rm`, then `safe /workspace/data`. The submitted text says `safe`.
    let target = args(&["/workspace/data"]);
    assert!(
        !allows(&policy, &run("safe /workspace/data", "rm", &target)),
        "the decision is about the program that RUNS, not the word that was typed"
    );
}

/// **Property 2.** The upgrade fail-open the two-action split exists to prevent.
///
/// An unconditional `permit` on `shell:exec` is the ordinary way to grant commands, and both
/// shipped examples carry one. It must not become a grant of host-binary execution the day
/// passthrough ships, without its author touching a line. `==` is exact, so it cannot — and
/// this test is what keeps that true if anyone proposes folding the two actions into one
/// with a flag.
#[test]
fn an_unconditional_run_grant_never_becomes_a_spawn_grant() {
    let policy = loaded(PERMIT_RUN);

    let target = args(&["-rf", "/"]);
    assert!(
        allows(&policy, &run("rm -rf /", "rm", &target)),
        "the resolved command it does grant"
    );
    assert!(
        !allows(
            &policy,
            &Request::ShellSpawn {
                command: "git push",
                program: "git",
                program_path: "/usr/bin/git",
                credential_reads: &[],
                args: &args(&["push"]),
                cwd: "/workspace",
            }
        ),
        "but not a host binary"
    );
}

/// **Property 3.** A permit for the programs the Shell implements does not reach a host
/// binary, whose effects escape `fs:*` admission entirely.
#[test]
fn permitting_shell_run_does_not_permit_a_host_binary() {
    let policy = loaded(PERMIT_RUN);

    let push = args(&["push", "origin", "main"]);
    assert!(
        !allows(
            &policy,
            &Request::ShellSpawn {
                command: "git push origin main",
                program: "git",
                program_path: "/usr/bin/git",
                credential_reads: &[],
                args: &push,
                cwd: "/workspace/repo",
            }
        ),
        "a host binary needs its own grant"
    );

    // With its own grant it is allowed, so the refusal above is the rule and not a
    // mapping fault.
    let both = loaded(&format!(
        r#"{PERMIT_RUN}
           permit (principal, action == Box::Action::"shell:spawn", resource);"#
    ));
    assert!(
        allows(
            &both,
            &Request::ShellSpawn {
                command: "git push origin main",
                program: "git",
                program_path: "/usr/bin/git",
                credential_reads: &[],
                args: &push,
                cwd: "/workspace/repo",
            }
        ),
        "an explicit shell:spawn permit grants it"
    );
}

/// `program_path` is what a rule pins to keep a permitted name from reaching a different
/// binary. The name is workload-influenced through `PATH`; the resolved path is what the
/// box will exec.
#[test]
fn a_spawn_rule_can_pin_the_resolved_binary_path() {
    let policy = loaded(
        r#"permit (principal, action == Box::Action::"shell:spawn", resource)
           when { context.input.program_path == "/usr/bin/git" };"#,
    );

    let push = args(&["push"]);
    let spawn = |program_path: &'static str| Request::ShellSpawn {
        command: "git push",
        program: "git",
        program_path,
        credential_reads: &[],
        args: &push,
        cwd: "/workspace",
    };

    assert!(allows(&policy, &spawn("/usr/bin/git")));
    assert!(
        !allows(&policy, &spawn("/workspace/.local/bin/git")),
        "a `git` earlier on PATH is a different binary and must not inherit the permit"
    );
}

/// `cwd` is required because identical arguments name different files from different
/// directories. `rm -rf data` is ordinary in a workspace and catastrophic at the root.
#[test]
fn identical_arguments_are_separated_by_the_working_directory() {
    let policy = loaded(
        r#"permit (principal, action == Box::Action::"shell:exec", resource)
           when { context.input.cwd like "/workspace*" };"#,
    );

    let relative = args(&["-rf", "data"]);
    let at = |cwd: &'static str| Request::ShellExec {
        command: "rm -rf data",
        program: "rm",
        args: &relative,
        cwd,
    };

    assert!(allows(&policy, &at("/workspace/app")));
    assert!(
        !allows(&policy, &at("/")),
        "the same argv from `/` is a different effect"
    );
}

/// `arg_count` lets a rule refuse a line longer than the two positions this schema
/// exposes, instead of silently missing what it cannot read.
#[test]
fn arg_count_bounds_a_line_the_named_positions_cannot_cover() {
    let policy = loaded(
        r#"permit (principal, action == Box::Action::"shell:exec", resource)
           when { context.input.arg_count <= 2 };"#,
    );

    assert!(allows(
        &policy,
        &run("rm -rf x", "rm", &args(&["-rf", "x"]))
    ));
    assert!(
        !allows(
            &policy,
            &run("rm a b c", "rm", &args(&["a", "b", "c", "d"]))
        ),
        "a fourth argument is beyond what arg1/arg2 can describe"
    );
}

/// `arg1` and `arg2` are optional, and reading one **unguarded is a load error**, not a
/// silent non-match.
///
/// This is the stronger of the two possible designs and the reason to keep the positions
/// optional rather than required-with-an-empty-string. An unguarded read cannot become a
/// rule that loads and quietly fails to match; strict validation refuses to guarantee the
/// access and aborts startup naming the attribute. Same shape as naming a removed action:
/// the author's mistake is loud.
#[test]
fn reading_an_optional_argument_unguarded_aborts_at_load() {
    let refused = support::open_policy(vec![Policy {
        origin: PathBuf::from("unguarded-arg.dw"),
        text: r#"permit (principal, action == Box::Action::"shell:exec", resource)
                 when { context.input.arg1 == "-rf" };"#
            .to_string(),
    }]);

    let message = match refused {
        Ok(_) => panic!("an unguarded optional read must not load"),
        Err(error) => error.to_string(),
    };
    assert!(
        message.contains("arg1"),
        "the refusal must name the attribute so an author can fix it: {message}"
    );
}

/// The guarded form is how an author reads a position, and it reports absence — so a rule
/// can describe "a command with no arguments at all".
#[test]
fn a_guarded_read_reports_an_absent_argument() {
    let guarded = loaded(
        r#"permit (principal, action == Box::Action::"shell:exec", resource)
           unless { context.input has arg1 };"#,
    );
    assert!(
        allows(&guarded, &run("pwd", "pwd", &[])),
        "a no-argument command is describable"
    );
    assert!(
        !allows(&guarded, &run("rm x", "rm", &args(&["x"]))),
        "and an argument-bearing one is excluded"
    );
}

/// There is no `shell` group, so covering both command actions takes two permits. An
/// operator who does not care to separate an internal program from a host binary writes one
/// clause per action. This is the accepted authoring cost of removing groups.
#[test]
fn covering_both_command_actions_needs_two_permits() {
    let policy = loaded(
        r#"permit (principal, action == Box::Action::"shell:exec", resource);
           permit (principal, action == Box::Action::"shell:spawn", resource);"#,
    );

    let target = args(&["x"]);
    assert!(allows(&policy, &run("rm x", "rm", &target)));
    assert!(allows(
        &policy,
        &Request::ShellSpawn {
            command: "git push",
            program: "git",
            program_path: "/usr/bin/git",
            credential_reads: &[],
            args: &target,
            cwd: "/workspace",
        }
    ));
}

/// The removed `shell` group name is a hard load error in **both** the `==` and `in` forms.
/// Were either accepted it would load and match nothing, which reads as "the rule did not
/// apply" rather than "the rule names an action that does not exist".
#[test]
fn the_removed_shell_group_name_is_a_hard_load_error() {
    for scope in [
        r#"action == Action::"shell""#,
        r#"action in [Action::"shell"]"#,
    ] {
        let refused = support::open_policy(vec![Policy {
            origin: PathBuf::from("removed-shell.dw"),
            text: format!("permit (principal, {scope}, resource);"),
        }]);
        assert!(
            refused.is_err(),
            "`{scope}` names a removed action and must abort at load"
        );
    }
}

/// A resolved run records its own `::response`, under the same action whose request was
/// authorized, so a rule can join a `shell:exec::request` to its own resolution and no other.
#[test]
fn a_resolved_run_records_history_under_its_own_action() {
    let policy = loaded(PERMIT_RUN);
    let words = args(&["-rf", "x"]);

    assert!(allows(&policy, &run("rm -rf x", "rm", &words)));
    policy
        .record(
            &governed(),
            &Principal::agent(),
            &Outcome::ShellRun {
                command: "rm -rf x",
                program: "rm",
                args: &words,
                cwd: "/workspace",
                status: 0,
            },
        )
        .expect("a resolved run is recordable as history");
}

/// A temporal rule counts resolved runs of one program. Keyed on `::response`, because a
/// `::request` predicate also matches an attempt policy refused — so a budget keyed on the
/// request is consumed by being denied.
#[test]
fn a_temporal_rule_counts_resolved_runs_of_one_program() {
    let policy = loaded(
        r#"permit (principal, action == Box::Action::"shell:exec", resource);
           forbid (principal, action == Box::Action::"shell:exec", resource)
           when temporal {
               (count for (t: Timepoint). where (
                   formerly within 1h (
                       Box::Action::"shell:exec"::response{ input.program: _ } && tp(t)
                   )
               )) > 2
           };"#,
    );

    let words = args(&["build"]);
    // Three runs are recorded, then the fourth attempt exceeds the budget.
    for _ in 0..3 {
        assert!(
            allows(&policy, &run("make build", "make", &words)),
            "a run inside the budget is permitted"
        );
        policy
            .record(
                &governed(),
                &Principal::agent(),
                &Outcome::ShellRun {
                    command: "make build",
                    program: "make",
                    args: &words,
                    cwd: "/workspace",
                    status: 0,
                },
            )
            .expect("history records");
    }

    assert!(
        !allows(&policy, &run("make build", "make", &words)),
        "the fourth run exceeds a budget of two prior resolutions"
    );
}

#[test]
fn credential_reads_are_present_only_on_a_punch_holed_spawn() {
    let policy = loaded(
        r#"permit (principal, action == Box::Action::"shell:spawn", resource);
           forbid (principal, action == Box::Action::"shell:spawn", resource)
           when {
               context.input has credential_reads &&
               context.input.credential_reads.contains("~/.aws")
           };"#,
    );
    let words = args(&["s3", "ls"]);
    let paths = vec!["~/.aws".to_string()];
    let spawn = |credential_reads| Request::ShellSpawn {
        command: "aws s3 ls",
        program: "aws",
        program_path: "/usr/local/bin/aws",
        credential_reads,
        args: &words,
        cwd: "/workspace",
    };

    assert!(
        allows(&policy, &spawn(&[])),
        "the optional field is absent without a punch-hole"
    );
    assert!(
        !allows(&policy, &spawn(&paths)),
        "the immediate decision sees the punch-holed path"
    );
}

#[test]
fn credential_reads_enter_durable_temporal_history() {
    let policy = loaded(
        r#"permit (principal, action == Box::Action::"shell:spawn", resource);
           permit (principal, action == Box::Action::"net:connect", resource);
           forbid (principal, action == Box::Action::"net:connect", resource)
           when temporal {
               formerly within 1h (
                   Box::Action::"shell:spawn"::response{ input.credential_reads: _ }
               )
           };"#,
    );
    let connect = Request::Connect {
        host: "api.example.com",
        ip: None,
        port: 443,
    };
    assert!(
        allows(&policy, &connect),
        "egress starts open before a credential-bearing leaf completes"
    );

    let words = args(&["s3", "ls"]);
    let paths = vec!["~/.aws".to_string()];
    policy
        .record(
            &governed(),
            &Principal::agent(),
            &Outcome::ShellSpawn {
                command: "aws s3 ls",
                program: "aws",
                program_path: "/usr/local/bin/aws",
                credential_reads: &paths,
                args: &words,
                cwd: "/workspace",
                status: 0,
            },
        )
        .expect("the credential-bearing outcome records");

    assert!(
        !allows(&policy, &connect),
        "the later decision sees the credential-bearing spawn in history"
    );
}
