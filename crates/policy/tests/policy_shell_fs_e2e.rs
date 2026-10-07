//! Authored Cedar `fs:*` rules govern real Shell effects, end to end.
//!
//! Before the kernel effect seam existed, the `fs:*` actions had no enforcement point: a
//! rule loaded, strict-validated, and then denied nothing. These tests run a real `Shell`
//! against a real `PolicyEngine` and assert the rules bite.

#![cfg(feature = "shell-adapter")]

mod support;

use std::path::PathBuf;
use std::sync::Arc;

use policy::{GovernedBox, Policy, Principal, ShellPolicyInterceptor};
use strands_shell::Shell;

/// Build a Shell whose kernel consults `source` for every effect.
fn shell_governed_by(source: &str) -> Shell {
    let policy = support::open_policy(vec![Policy {
        origin: PathBuf::from("shell-fs-e2e.cedar"),
        text: source.to_string(),
    }])
    .expect("policy opens");
    let interceptor = ShellPolicyInterceptor::into_handle(
        Arc::new(policy),
        Principal::agent(),
        GovernedBox::assigned("test-box"),
    );
    Shell::builder()
        .effect_interceptor(interceptor)
        .build()
        .expect("shell builds")
}

fn run<F, T>(body: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds");
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(body))
}

/// Permit everything the shell needs, so a test can then subtract one rule.
const PERMIT_ALL: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);
"#;

/// Permit `fs:read` and `fs:write` below one project directory, and nothing above it.
const PROJECT_SCOPED: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.path like "/home/lash/project/*" };
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when { context.input.path like "/home/lash/project/*" };
"#;

#[test]
fn a_shell_command_denial_returns_the_policy_description() {
    let mut shell = shell_governed_by(
        r#"@id("blocked-command")
           @description("This workload cannot run this command.")
           forbid(principal, action == Box::Action::"shell:exec", resource);"#,
    );
    let output = run(shell.run("echo hidden"));
    assert_eq!(output.status, 126);
    assert!(output.stdout.is_empty());
    assert!(
        output.stderr.contains(
            "policy denied this operation on 'echo' [policy: blocked-command]: This workload cannot run this command."
        ),
        "{}",
        output.stderr
    );
}

#[test]
fn a_shell_content_denial_returns_the_policy_description() {
    let (mut fixture, mut shell) = fixture_and_governed(&format!(
        r#"{PERMIT_ALL}
           @id("protected-content")
           @description("This file contains protected information.")
           forbid(principal, action == Box::Action::"fs:read", resource)
           when {{
               context.input.operation == Box::FsReadOperation::"read_content" &&
               context.input.path == "/home/lash/secret.txt"
           }};"#
    ));
    let output = run(async {
        assert_eq!(
            fixture
                .run("printf secret > /home/lash/secret.txt")
                .await
                .status,
            0
        );
        shell.run("cat /home/lash/secret.txt").await
    });
    assert_ne!(output.status, 0);
    assert!(!output.stdout.contains("secret"));
    assert!(
        output
            .stderr
            .contains("This file contains protected information."),
        "{}",
        output.stderr
    );
}

/// **A refusal names the file it refused**, in the spelling a rule reads, and no other file on
/// the same command line.
#[test]
fn a_multi_file_denial_names_only_the_denied_file() {
    let (mut fixture, mut shell) = fixture_and_governed_reporting(
        &format!(
            r#"{PERMIT_ALL}
           @id("no-secrets")
           @description("Secrets stay unread.")
           forbid(principal, action == Box::Action::"fs:read", resource)
           when {{
               context.input.operation == Box::FsReadOperation::"read_content" &&
               context.input.path == "~/notes.txt"
           }};"#
        ),
        Some("/home/lash"),
    );
    let output = run(async {
        for (name, content) in [
            ("a.txt", "alpha"),
            ("notes.txt", "secret"),
            ("b.txt", "beta"),
        ] {
            let status = fixture
                .run(&format!("printf {content} > /home/lash/{name}"))
                .await
                .status;
            assert_eq!(status, 0, "{name}");
        }
        shell
            .run("cat /home/lash/a.txt /home/lash/notes.txt /home/lash/b.txt")
            .await
    });
    assert_ne!(output.status, 0);
    assert!(!output.stdout.contains("secret"), "{}", output.stdout);
    assert!(
        output.stderr.contains(
            "policy denied this operation on '~/notes.txt' [policy: no-secrets]: Secrets stay unread."
        ),
        "{}",
        output.stderr
    );
    assert!(
        !output.stderr.contains("a.txt") && !output.stderr.contains("b.txt"),
        "{}",
        output.stderr
    );
}

/// An ungoverned Shell and a governed one over the **same** kernel.
///
/// A test that guards a path cannot also create the fixture under it — the rule denies
/// its own precondition, and loosening the rule to permit setup leaves a hole the
/// payload slips through too. Sharing one kernel shares one VFS, so the fixture shell
/// builds the protected file and the governed shell then attacks it.
fn fixture_and_governed(source: &str) -> (Shell, Shell) {
    fixture_and_governed_reporting(source, None)
}

/// The same pair, with every path under `home` reported to policy as `~/<relative>`.
fn fixture_and_governed_reporting(source: &str, home: Option<&str>) -> (Shell, Shell) {
    let policy = Arc::new(
        support::open_policy(vec![Policy {
            origin: PathBuf::from("shell-fs-e2e-shared.cedar"),
            text: source.to_string(),
        }])
        .expect("policy opens"),
    );
    let (principal, governed) = (Principal::agent(), GovernedBox::assigned("test-box"));
    let interceptor = match home {
        Some(home) => {
            ShellPolicyInterceptor::into_handle_reporting_under(policy, principal, governed, home)
        }
        None => ShellPolicyInterceptor::into_handle(policy, principal, governed),
    };
    let vfs = strands_shell::vfs_config::build_vfs(&Default::default()).expect("standard vfs");
    let kernel: Arc<dyn strands_shell::os::Kernel> =
        Arc::new(strands_shell::vfs_kernel::VfsKernel::new(vfs));

    let fixture = Shell::builder()
        .kernel(Arc::clone(&kernel))
        .build()
        .expect("fixture shell builds");
    let governed = Shell::builder()
        .effect_interceptor(interceptor)
        .kernel(kernel)
        .build()
        .expect("governed shell builds");
    (fixture, governed)
}

/// Build a Shell governed by `source`, over a caller-supplied kernel.
///
/// The kernel is a bare `VfsKernel` handed in through `ShellBuilder::kernel`, which is
/// the shape an embedder uses for an S3- or database-backed backend. Admission lives
/// above the `Kernel` trait, so this must be governed exactly as the bundled kernel is;
/// before the seam moved, every filesystem effect here went unmediated.
fn supplied_kernel_governed_by(source: &str) -> Shell {
    let policy = support::open_policy(vec![Policy {
        origin: PathBuf::from("shell-fs-e2e-supplied.cedar"),
        text: source.to_string(),
    }])
    .expect("policy opens");
    let interceptor = ShellPolicyInterceptor::into_handle(
        Arc::new(policy),
        Principal::agent(),
        GovernedBox::assigned("test-box"),
    );
    let vfs = strands_shell::vfs_config::build_vfs(&Default::default()).expect("standard vfs");
    let kernel: Arc<dyn strands_shell::os::Kernel> =
        Arc::new(strands_shell::vfs_kernel::VfsKernel::new(vfs));
    Shell::builder()
        .effect_interceptor(interceptor)
        .kernel(kernel)
        .build()
        .expect("shell builds")
}

/// The baseline: with `fs:*` permitted, ordinary work succeeds.
#[test]
fn permitted_filesystem_effects_succeed() {
    let mut shell = shell_governed_by(PERMIT_ALL);
    let out = run(async {
        shell
            .run("mkdir -p /home/lash/p && printf 'hi' > /home/lash/p/f && cat /home/lash/p/f")
            .await
    });
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(out.stdout, "hi");
}

/// A `forbid` on `fs:write` stops the write even though `shell:exec` is permitted.
///
/// This is the property that did not hold before the kernel seam: the command was
/// admitted and the write happened regardless of any `fs:write` rule.
#[test]
fn forbidding_fs_write_blocks_a_write_under_a_permitted_command() {
    let mut shell = shell_governed_by(&format!(
        r#"{PERMIT_ALL}
           forbid(principal, action == Box::Action::"fs:write", resource)
           when {{ context.input.path like "*/protected/*" }};"#
    ));

    let (setup, blocked, elsewhere) = run(async {
        let setup = shell.run("mkdir -p /home/lash/open").await;
        let blocked = shell.run("printf 'x' > /home/lash/protected/secret").await;
        let elsewhere = shell.run("printf 'x' > /home/lash/open/fine").await;
        (setup, blocked, elsewhere)
    });

    assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
    assert_ne!(blocked.status, 0, "a forbidden write must fail");
    assert_eq!(
        elsewhere.status, 0,
        "an unrelated write still succeeds: {}",
        elsewhere.stderr
    );
}

/// A `forbid` on `fs:read` hides content the shell could otherwise cat.
#[test]
fn forbidding_fs_read_blocks_reading_that_path() {
    let mut shell = shell_governed_by(&format!(
        r#"{PERMIT_ALL}
           forbid(principal, action == Box::Action::"fs:read", resource)
           when {{ context.input.path == "/home/lash/secret.txt" }};"#
    ));

    let (written, read_back, other) = run(async {
        let written = shell
            .run("printf 'classified' > /home/lash/secret.txt && printf 'public' > /home/lash/ok.txt")
            .await;
        let read_back = shell.run("cat /home/lash/secret.txt").await;
        let other = shell.run("cat /home/lash/ok.txt").await;
        (written, read_back, other)
    });

    assert_eq!(written.status, 0, "setup: {}", written.stderr);
    assert!(
        !read_back.stdout.contains("classified"),
        "a forbidden read must not disclose content: {:?}",
        read_back.stdout
    );
    assert_eq!(other.stdout, "public", "an unrelated read still works");
}

/// The rule binds the resolved path, so a relative spelling cannot evade it.
///
/// The kernel admits the path after applying the working directory, so `cd` plus a
/// bare filename reaches policy as the same canonical string as the absolute form.
#[test]
fn a_relative_spelling_cannot_evade_a_path_rule() {
    let mut shell = shell_governed_by(&format!(
        r#"{PERMIT_ALL}
           forbid(principal, action == Box::Action::"fs:read", resource)
           when {{ context.input.path == "/home/lash/vault/key" }};"#
    ));

    let (setup, absolute, relative, dotted) = run(async {
        let setup = shell
            .run("mkdir -p /home/lash/vault && printf 'KEY' > /home/lash/vault/key")
            .await;
        let absolute = shell.run("cat /home/lash/vault/key").await;
        let relative = shell.run("cd /home/lash/vault && cat key").await;
        let dotted = shell.run("cd /home/lash/vault && cat ./../vault/key").await;
        (setup, absolute, relative, dotted)
    });

    assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
    for (label, out) in [
        ("absolute", absolute),
        ("relative", relative),
        ("dotted", dotted),
    ] {
        assert!(
            !out.stdout.contains("KEY"),
            "the {label} spelling must be denied too: {:?}",
            out.stdout
        );
    }
}

/// Absent authored `fs:*` permits, filesystem effects are denied by default.
#[test]
fn filesystem_effects_are_denied_without_a_permit() {
    let mut shell = shell_governed_by(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);"#,
    );

    let out = run(async { shell.run("printf 'x' > /home/lash/anything").await });
    assert_ne!(
        out.status, 0,
        "with no fs:write permit the write must be denied"
    );
}

#[test]
fn ordinary_filenames_follow_the_shells_authored_policy() {
    let mut shell = shell_governed_by(PERMIT_ALL);

    let outputs = run(async {
        let mut outputs = Vec::new();
        for file in ["box.toml", "policy.dw", "notes.txt"] {
            outputs.push((
                file,
                shell
                    .run(&format!("printf 'fine' > /home/lash/{file}"))
                    .await,
            ));
        }
        outputs
    });

    for (file, output) in outputs {
        assert_eq!(
            output.status, 0,
            "the authored permit must govern {file}: {}",
            output.stderr
        );
    }
}

// Removed: `a_host_rule_survives_url_respelling` and `an_unreadable_url_is_denied`.
//
// Both exercised this adapter parsing a request URL into host, port, and path. The
// Shell no longer raises a network attempt, so there is no URL here to parse and no
// respelling to defend against.
//
// The class does not reappear at the egress boundary: `EgressEffectAttempt::HttpRequest`
// arrives with `host` and `port` already separated by the proxy that terminated the
// connection, so no policy decision is made from a URL string. Egress request
// authorization is covered by `tests/policy_egress_e2e.rs`.

// Removed: `credential_use_is_authorized_against_the_egress_principal`.
//
// It exercised a Shell-side `cred:inject` decision. The Shell now holds no
// credentials and raises no credential attempt — injection is wholly the egress
// boundary's action, covered by `tests/policy_credential_e2e.rs` against
// `EgressPolicyInterceptor`. Keeping a Shell-principal version would assert a
// control this crate no longer provides.

/// An authored path rule holds against every mutating operation, not just writes.
///
/// The seam's headline fix, proven against real Cedar rather than a test double. Two
/// live bypasses were found in this class: `mv` (the reported one) and
/// `rm`/`rmdir`/`chmod` (found by sweeping the class rather than the case). Both existed
/// because a per-method judgment about symlink resolution was wrong in one place.
///
/// The rule guards `*/vault/keep*`, and the fixture writes `/vault/keep*` **before**
/// naming them through the alias. One shell throughout — a second one would have its
/// own VFS and see nothing. The setup writes are permitted because they name the
/// canonical path directly and the rule's `forbid` is scoped to the alias-reachable
/// attack, so the precondition is honest rather than carved out of the predicate.
#[test]
fn a_path_rule_holds_through_a_directory_symlink_for_every_operation() {
    let (mut fixture, mut shell) = fixture_and_governed(&format!(
        r#"{PERMIT_ALL}
           forbid(
               principal,
               action in [Box::Action::"fs:read", Box::Action::"fs:write", Box::Action::"fs:delete", Box::Action::"fs:move"],
               resource
           )
           when {{ context.input.path like "*/vault/*" }};"#
    ));

    let (setup, cases, survived, listing) = run(async {
        // The UNGOVERNED shell builds the fixture, so the guarded file genuinely exists
        // before the attack. Sharing the kernel means the governed shell sees it.
        let setup = fixture
            .run(
                "mkdir -p /home/lash/vault/keepdir \
                 && printf 'original' > /home/lash/vault/keepfile \
                 && printf 'payload' > /home/lash/src \
                 && ln -s /home/lash/vault /home/lash/alias",
            )
            .await;

        // Every one of these reaches the guarded subtree ONLY through the alias, whose
        // own spelling the rule does not match.
        let cases = vec![
            ("read", shell.run("cat /home/lash/alias/keepfile").await),
            (
                "write",
                shell
                    .run("printf 'PWNED' > /home/lash/alias/keepfile")
                    .await,
            ),
            (
                "mv",
                shell
                    .run("mv /home/lash/src /home/lash/alias/keepfile")
                    .await,
            ),
            ("rm", shell.run("rm /home/lash/alias/keepfile").await),
            ("rmdir", shell.run("rmdir /home/lash/alias/keepdir").await),
            (
                "chmod",
                shell.run("chmod 777 /home/lash/alias/keepfile").await,
            ),
            ("mkdir", shell.run("mkdir /home/lash/alias/keepnew").await),
        ];

        // Read back with the UNGOVERNED shell: the fixture must be untouched.
        let survived = fixture.run("cat /home/lash/vault/keepfile").await;
        let listing = fixture.run("ls /home/lash/vault").await;
        (setup, cases, survived, listing)
    });

    assert_eq!(setup.status, 0, "setup: {}", setup.stderr);

    for (label, out) in &cases {
        assert_ne!(
            out.status, 0,
            "{label} through a directory symlink must be denied by the path rule: {}",
            out.stderr
        );
    }
    // Nothing may have landed under the guard by any of those routes.
    assert!(
        !survived.stdout.contains("PWNED"),
        "no operation may place content in the guarded subtree: {:?}",
        survived.stdout
    );
    assert!(
        !listing.stdout.contains("keepnew"),
        "no directory may be created in the guarded subtree: {:?}",
        listing.stdout
    );
    assert_eq!(
        survived.stdout, "original",
        "the guarded file's content must be untouched by every denied route"
    );
    assert!(
        listing.stdout.contains("keepdir"),
        "rmdir through the alias must not have removed the guarded directory: {:?}",
        listing.stdout
    );
}

/// `mv` still moves a link rather than the file it points at.
///
/// The counterpart to the test above: closing the laundering hole must not break
/// ordinary symlink semantics. `rename` resolves its *destination* (so a symlinked
/// target directory is judged correctly) but not its *source* (so the link itself
/// moves). Getting the source wrong moved the target instead and broke `readlink`.
#[test]
fn moving_a_symlink_moves_the_link_not_its_target() {
    let mut shell = shell_governed_by(PERMIT_ALL);

    let (moved, target, still_there) = run(async {
        let setup = shell
            .run(
                "printf 'content' > /home/lash/real \
                 && ln -s /home/lash/real /home/lash/link",
            )
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        let moved = shell.run("mv /home/lash/link /home/lash/link2").await;
        let target = shell.run("readlink /home/lash/link2").await;
        let still_there = shell.run("cat /home/lash/real").await;
        (moved, target, still_there)
    });

    assert_eq!(
        moved.status, 0,
        "moving a link is permitted: {}",
        moved.stderr
    );
    assert_eq!(
        target.stdout.trim(),
        "/home/lash/real",
        "the moved link must still name its original target"
    );
    assert_eq!(
        still_there.stdout, "content",
        "the target file must be untouched by moving the link"
    );
}

/// `mv` onto an existing file is refused by a `forbid` on deleting that file, and the same `mv`
/// onto an absent name is a plain move.
#[test]
fn an_overwriting_rename_is_refused_by_a_forbid_on_deleting_the_destination() {
    let (mut fixture, mut shell) = fixture_and_governed(&format!(
        r#"{PERMIT_ALL}
           @id("no-delete")
           forbid(principal, action == Box::Action::"fs:delete", resource)
           when {{ context.input.path == "/home/lash/protected" }};"#
    ));

    let (setup, overwrite, survived, fresh, moved) = run(async {
        let setup = fixture
            .run("printf 'original' > /home/lash/protected && printf 'PWNED' > /home/lash/payload")
            .await;
        let overwrite = shell
            .run("mv /home/lash/payload /home/lash/protected")
            .await;
        let survived = fixture.run("cat /home/lash/protected").await;
        let fresh = shell.run("mv /home/lash/payload /home/lash/fresh").await;
        let moved = fixture.run("cat /home/lash/fresh").await;
        (setup, overwrite, survived, fresh, moved)
    });

    assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
    assert_ne!(
        overwrite.status, 0,
        "mv onto a file whose deletion is forbidden must fail"
    );
    assert!(
        overwrite
            .stderr
            .contains("policy denied this operation on '/home/lash/protected' [policy: no-delete]"),
        "{}",
        overwrite.stderr
    );
    assert_eq!(
        survived.stdout, "original",
        "the protected file's content must be untouched"
    );
    assert_eq!(
        fresh.status, 0,
        "the same mv onto an absent name is a plain move: {}",
        fresh.stderr
    );
    assert_eq!(moved.stdout, "PWNED", "the plain move carried the bytes");
}

/// Without an `fs:delete` permit, `mv` onto an existing file is refused by default-deny, while
/// `fs:move` alone still carries a rename onto an absent name.
#[test]
fn an_overwriting_rename_needs_an_fs_delete_permit() {
    const WITHOUT_DELETE: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);
"#;
    let (mut fixture, mut shell) = fixture_and_governed(WITHOUT_DELETE);

    let (setup, overwrite, survived, fresh, moved) = run(async {
        let setup = fixture
            .run("printf 'original' > /home/lash/existing && printf 'PWNED' > /home/lash/payload")
            .await;
        let overwrite = shell.run("mv /home/lash/payload /home/lash/existing").await;
        let survived = fixture.run("cat /home/lash/existing").await;
        let fresh = shell.run("mv /home/lash/payload /home/lash/fresh").await;
        let moved = fixture.run("cat /home/lash/fresh").await;
        (setup, overwrite, survived, fresh, moved)
    });

    assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
    assert_ne!(
        overwrite.status, 0,
        "mv onto an existing file needs an fs:delete permit"
    );
    assert!(
        overwrite
            .stderr
            .contains("policy denied this operation on '/home/lash/existing' [default-deny]"),
        "{}",
        overwrite.stderr
    );
    assert_eq!(
        survived.stdout, "original",
        "the existing file's content must be untouched"
    );
    assert_eq!(
        fresh.status, 0,
        "fs:move alone carries a rename onto an absent name: {}",
        fresh.stderr
    );
    assert_eq!(moved.stdout, "PWNED", "the plain move carried the bytes");
}

/// A dangling symlink at the destination is a bound name, so `mv` onto it needs `fs:delete`.
#[test]
fn a_rename_onto_a_dangling_symlink_needs_fs_delete() {
    let (mut fixture, mut shell) = fixture_and_governed(&format!(
        r#"{PERMIT_ALL}
           @id("no-delete")
           forbid(principal, action == Box::Action::"fs:delete", resource)
           when {{ context.input.path == "/home/lash/dangling" }};"#
    ));

    let (setup, overwrite, kind) = run(async {
        let setup = fixture
            .run("ln -s /home/lash/nowhere /home/lash/dangling && printf 'PWNED' > /home/lash/payload")
            .await;
        let overwrite = shell.run("mv /home/lash/payload /home/lash/dangling").await;
        let kind = fixture.run("readlink /home/lash/dangling").await;
        (setup, overwrite, kind)
    });

    assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
    assert_ne!(
        overwrite.status, 0,
        "mv onto a dangling symlink whose deletion is forbidden must fail"
    );
    assert!(
        overwrite
            .stderr
            .contains("policy denied this operation on '/home/lash/dangling' [policy: no-delete]"),
        "{}",
        overwrite.stderr
    );
    assert_eq!(
        kind.stdout.trim(),
        "/home/lash/nowhere",
        "the dangling symlink must still be a symlink to its original target"
    );
}

/// A relative symlink keeps its relativity through the seam.
///
/// `ln -s d /home/lash/link` stores the literal text `d`, resolved later against the
/// link's own directory. The seam must not absolutize it: `symlink`'s target is stored
/// data, not a path the call acts on. An earlier revision made it a resolved token and
/// silently rewrote every relative link.
#[test]
fn a_relative_symlink_is_stored_verbatim() {
    let mut shell = shell_governed_by(PERMIT_ALL);

    let (stored, through_link) = run(async {
        let setup = shell
            .run("mkdir -p /home/lash/d && printf 'ok' > /home/lash/d/file && ln -s d /home/lash/link")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        let stored = shell.run("readlink /home/lash/link").await;
        let through_link = shell.run("cat /home/lash/link/file").await;
        (stored, through_link)
    });

    assert_eq!(
        stored.stdout.trim(),
        "d",
        "a relative link must be stored exactly as written"
    );
    assert_eq!(
        through_link.stdout, "ok",
        "and must still resolve against its own directory"
    );
}

/// A `forbid` on one path removes only that path from a glob expansion.
///
/// Pattern expansion is the enumeration channel: one call decides which files a later
/// loop touches. A path rule cannot match a pattern (`*/vault/*` never matches the
/// literal `/home/lash/w/*`), so the seam authorizes the directory being enumerated and
/// then each match individually. This asserts the per-match half — a denied entry drops
/// from the expansion while its siblings survive.
#[test]
fn a_forbidden_match_drops_from_a_glob_expansion() {
    let mut shell = shell_governed_by(&format!(
        r#"{PERMIT_ALL}
           forbid(principal, action == Box::Action::"fs:read", resource)
           when {{ context.input.path == "/home/lash/w/secret.txt" }};"#
    ));

    let listed = run(async {
        let setup = shell
            .run(
                "mkdir -p /home/lash/w \
                 && printf 'a' > /home/lash/w/public.txt \
                 && printf 'b' > /home/lash/w/secret.txt \
                 && printf 'c' > /home/lash/w/other.txt",
            )
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        shell
            .run("for f in /home/lash/w/*.txt; do echo $f; done")
            .await
    });

    assert!(
        listed.stdout.contains("public.txt") && listed.stdout.contains("other.txt"),
        "permitted matches must survive the expansion: {:?}",
        listed.stdout
    );
    assert!(
        !listed.stdout.contains("secret.txt"),
        "a forbidden match must drop from the expansion: {:?}",
        listed.stdout
    );
}

/// A caller-supplied kernel is governed by the same authored rules.
///
/// The seam's other headline property. Admission sits above the `Kernel` trait, so an
/// embedder's own backend cannot decide whether policy applies. Before the move,
/// `.effect_interceptor(p).kernel(k)` compiled, warned nothing, and enforced the
/// command rule only — every file effect underneath went unchecked.
#[test]
fn a_supplied_kernel_is_governed_by_the_same_rules() {
    let mut shell = supplied_kernel_governed_by(&format!(
        r#"{PERMIT_ALL}
           forbid(principal, action == Box::Action::"fs:write", resource)
           when {{ context.input.path like "*/guarded/*" }};"#
    ));

    let (blocked, elsewhere, content) = run(async {
        let setup = shell
            .run("mkdir -p /home/lash/guarded && printf 'original' > /home/lash/guarded/f")
            .await;
        // The setup write is itself forbidden, so create the file where the rule does
        // not reach and prove the guarded path stays unwritable.
        assert_ne!(
            setup.status, 0,
            "the rule applies to a supplied kernel from the first write"
        );
        let blocked = shell.run("printf 'PWNED' > /home/lash/guarded/f").await;
        let elsewhere = shell.run("printf 'fine' > /home/lash/open.txt").await;
        let content = shell.run("cat /home/lash/open.txt").await;
        (blocked, elsewhere, content)
    });

    assert_ne!(
        blocked.status, 0,
        "a supplied kernel must not escape an authored rule"
    );
    assert_eq!(
        elsewhere.status, 0,
        "an unrelated write still succeeds under a supplied kernel: {}",
        elsewhere.stderr
    );
    assert_eq!(content.stdout, "fine", "and its content is readable back");
}

/// One `Output`, rendered for an assertion message.
fn rendered(out: &strands_shell::Output) -> String {
    format!(
        "status={} stdout={:?} stderr={:?}",
        out.status, out.stdout, out.stderr
    )
}

/// A `forbid` on the `exec` probe of the program a `PATH` walk selects keeps it from running.
#[test]
fn forbidding_the_selected_candidates_exec_probe_keeps_it_from_running() {
    let (mut fixture, mut shell) = fixture_and_governed(&format!(
        r#"{PERMIT_ALL}
           @id("no-tool")
           forbid(principal, action == Box::Action::"fs:read", resource)
           when {{
               context.input.operation == Box::FsReadOperation::"exec" &&
               context.input.path == "/home/lash/bin/tool"
           }};"#
    ));
    let out = run(async {
        let planted = fixture
            .run(
                "mkdir -p /home/lash/bin && \
                 printf '#!/bin/sh\\necho RAN\\n' > /home/lash/bin/tool && \
                 chmod +x /home/lash/bin/tool",
            )
            .await;
        assert_eq!(planted.status, 0, "setup: {}", planted.stderr);
        shell.set_env("PATH", "/home/lash/bin");
        shell.run("tool").await
    });
    assert_ne!(out.status, 0, "{}", rendered(&out));
    assert!(
        !out.stdout.contains("RAN"),
        "the forbidden program must not run: {}",
        rendered(&out)
    );
    assert!(
        out.stderr.contains("tool: command not found"),
        "a refused candidate is absent: {}",
        rendered(&out)
    );
}

/// A pair whose fixture already holds `/home/lash/project`, governed by [`PROJECT_SCOPED`].
fn project_fixture_and_governed() -> (Shell, Shell) {
    let (mut fixture, shell) = fixture_and_governed(PROJECT_SCOPED);
    let setup = run(fixture.run("mkdir -p /home/lash/project"));
    assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
    (fixture, shell)
}

/// `mkdir -p` with an absolute path creates each missing component below the grant.
///
/// The ancestors above the grant exist, and policy refuses to say so. The builtin must
/// not create what it cannot see.
#[test]
fn mkdir_p_with_an_absolute_path_creates_every_missing_component_below_a_grant() {
    let (mut fixture, mut shell) = project_fixture_and_governed();
    let (made, listing) = run(async {
        let made = shell.run("mkdir -p /home/lash/project/c/d").await;
        let listing = fixture.run("ls /home/lash/project/c").await;
        (made, listing)
    });
    assert_eq!(made.status, 0, "{}", rendered(&made));
    assert!(made.stderr.is_empty(), "{}", rendered(&made));
    assert_eq!(listing.stdout.trim(), "d", "{}", rendered(&listing));
}

/// `mkdir -p` with a relative path still creates each missing component.
#[test]
fn mkdir_p_with_a_relative_path_creates_every_missing_component() {
    let (mut fixture, mut shell) = project_fixture_and_governed();
    shell.proc.cwd = PathBuf::from("/home/lash/project");
    let (made, listing) = run(async {
        let made = shell.run("mkdir -p a/b").await;
        let listing = fixture.run("ls /home/lash/project/a").await;
        (made, listing)
    });
    assert_eq!(made.status, 0, "{}", rendered(&made));
    assert_eq!(listing.stdout.trim(), "b", "{}", rendered(&listing));
}

/// `mkdir -p` below an ungranted parent is refused, and the refusal names the target.
#[test]
fn mkdir_p_below_an_ungranted_parent_is_refused_and_names_the_target() {
    let (mut fixture, mut shell) = project_fixture_and_governed();
    let (refused, listing) = run(async {
        let refused = shell.run("mkdir -p /home/lash/other/x").await;
        let listing = fixture.run("ls /home/lash").await;
        (refused, listing)
    });
    assert_ne!(refused.status, 0, "{}", rendered(&refused));
    assert!(
        refused
            .stderr
            .contains("policy denied this operation on '/home/lash/other/x' [default-deny]"),
        "{}",
        rendered(&refused)
    );
    assert!(
        !refused.stderr.contains("'/home'"),
        "the refusal must not name an ancestor: {}",
        rendered(&refused)
    );
    assert!(
        !listing.stdout.contains("other"),
        "nothing may be created above the grant: {}",
        rendered(&listing)
    );
}

/// Plain `mkdir` is unchanged: permitted below the grant, refused by name above it.
#[test]
fn plain_mkdir_is_unchanged_by_the_parents_walk() {
    let (_fixture, mut shell) = project_fixture_and_governed();
    let (below, above) = run(async {
        let below = shell.run("mkdir /home/lash/project/e").await;
        let above = shell.run("mkdir /home/lash/e").await;
        (below, above)
    });
    assert_eq!(below.status, 0, "{}", rendered(&below));
    assert_ne!(above.status, 0, "{}", rendered(&above));
    assert!(
        above
            .stderr
            .contains("policy denied this operation on '/home/lash/e' [default-deny]"),
        "{}",
        rendered(&above)
    );
}
