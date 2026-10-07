//! The record kind each filesystem effect leaves, through the hosted Shell on a direct host bind.

#![cfg(feature = "shell-adapter")]

mod support;

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use policy::{GovernedBox, Policy, Principal, ShellPolicyInterceptor};
use strands_shell::{Output, Shell};

/// A Shell over `project`, bound directly at `/work`, governed by `source`.
fn shell_over(project: &Path, source: &str) -> Shell {
    let policy = support::open_policy(vec![Policy {
        origin: PathBuf::from("shell-record-kinds.dw"),
        text: source.to_string(),
    }])
    .expect("policy opens");
    let interceptor = ShellPolicyInterceptor::into_handle(
        Arc::new(policy),
        Principal::agent(),
        GovernedBox::assigned("test-box"),
    );
    Shell::builder()
        .bind_direct(project.display().to_string(), "/work")
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

/// A project directory holding one regular file, `file`.
fn project() -> tempfile::TempDir {
    let project = tempfile::tempdir().expect("a project directory");
    std::fs::write(project.path().join("file"), "payload").expect("the project file");
    project
}

/// `fs:read` and `fs:write` below the project, and nothing else.
const PROJECT_SCOPED: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.path == "/work" || context.input.path like "/work/*" };
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when { context.input.path == "/work" || context.input.path like "/work/*" };
"#;

/// `fs:read` and `fs:write` everywhere.
const UNSCOPED: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
"#;

/// Two probe writes for one operation: one forbidden once history holds its `::response`, one
/// forbidden once history holds its `::error`.
fn probes(name: &str, action: &str, operation: &str) -> String {
    format!(
        r#"
@id("{name}-landed")
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when {{ context.input.path == "/work/probe-{name}-landed" }}
when temporal {{
    formerly within 3600s (
        Box::Action::"{action}"::response{{ input.path: _, input.operation: {operation} }}
    )
}};
@id("{name}-failed")
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when {{ context.input.path == "/work/probe-{name}-failed" }}
when temporal {{
    formerly within 3600s (
        Box::Action::"{action}"::error{{ input.path: _, input.operation: {operation} }}
    )
}};
"#
    )
}

const CHMOD_PROBES: (&str, &str, &str) = (
    "chmod",
    "fs:write",
    r#"Box::FsWriteOperation::"set_permissions""#,
);
const SYMLINK_PROBES: (&str, &str, &str) =
    ("symlink", "fs:write", r#"Box::FsWriteOperation::"symlink""#);
const READLINK_PROBES: (&str, &str, &str) = (
    "readlink",
    "fs:read",
    r#"Box::FsReadOperation::"read_link""#,
);

fn governed_by(base: &str, (name, action, operation): (&str, &str, &str)) -> String {
    format!("{base}{}", probes(name, action, operation))
}

/// Which record kind the probes say history holds for `name`: `Some(true)` landed, `Some(false)`
/// failed, `None` neither.
async fn recorded_kind(shell: &mut Shell, project: &Path, name: &str) -> Option<bool> {
    let landed = probe(shell, project, &format!("{name}-landed")).await;
    let failed = probe(shell, project, &format!("{name}-failed")).await;
    match (landed, failed) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        (false, false) => None,
        (true, true) => panic!("one effect must not record both a response and an error"),
    }
}

/// Whether the forbid named `probe` refused the probe write, with the file absent on the host.
async fn probe(shell: &mut Shell, project: &Path, probe: &str) -> bool {
    let written = shell.run(&format!("echo x > /work/probe-{probe}")).await;
    let on_host = project.join(format!("probe-{probe}")).is_file();
    let refused = written.stderr.contains(&format!("[policy: {probe}]"));
    assert_eq!(
        (written.status == 0, on_host),
        (!refused, !refused),
        "a probe write is refused by its forbid or lands, never half: {}",
        rendered(&written)
    );
    refused
}

fn rendered(out: &Output) -> String {
    format!(
        "status={} stdout={:?} stderr={:?}",
        out.status, out.stdout, out.stderr
    )
}

fn assert_admitted_then_failed(out: &Output) {
    assert_ne!(out.status, 0, "{}", rendered(out));
    assert!(
        !out.stderr.contains("policy denied"),
        "the effect must be admitted and fail afterwards: {}",
        rendered(out)
    );
}

#[test]
fn a_chmod_that_lands_records_a_response_and_charges_the_set_permissions_budget() {
    let project = project();
    let mut shell = shell_over(project.path(), &governed_by(PROJECT_SCOPED, CHMOD_PROBES));
    let kind = run(async {
        let changed = shell.run("chmod 600 /work/file").await;
        assert_eq!(changed.status, 0, "{}", rendered(&changed));
        recorded_kind(&mut shell, project.path(), "chmod").await
    });
    let mode = std::fs::metadata(project.path().join("file"))
        .expect("the file")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the effect is visible on the host");
    assert_eq!(kind, Some(true));
}

#[test]
fn a_chmod_that_fails_records_an_error_and_charges_nothing() {
    let project = project();
    let mut shell = shell_over(project.path(), &governed_by(PROJECT_SCOPED, CHMOD_PROBES));
    let kind = run(async {
        let changed = shell.run("chmod 600 /work/missing").await;
        assert_admitted_then_failed(&changed);
        recorded_kind(&mut shell, project.path(), "chmod").await
    });
    assert_eq!(kind, Some(false));
}

#[test]
fn a_symlink_to_an_absolute_target_is_admitted_refused_by_the_kernel_and_records_an_error() {
    let project = project();
    let mut shell = shell_over(project.path(), &governed_by(PROJECT_SCOPED, SYMLINK_PROBES));
    let kind = run(async {
        let linked = shell.run("ln -s /work/file /work/link").await;
        assert_admitted_then_failed(&linked);
        assert!(
            linked.stderr.contains("escapes the bind mount"),
            "{}",
            rendered(&linked)
        );
        recorded_kind(&mut shell, project.path(), "symlink").await
    });
    assert!(
        std::fs::symlink_metadata(project.path().join("link")).is_err(),
        "a refused symlink leaves nothing on the host"
    );
    assert_eq!(kind, Some(false));
}

#[test]
fn a_symlink_that_lands_records_a_response_and_charges_the_symlink_budget() {
    let project = project();
    let mut shell = shell_over(project.path(), &governed_by(UNSCOPED, SYMLINK_PROBES));
    let kind = run(async {
        let linked = shell.run("ln -s file /work/link").await;
        assert_eq!(linked.status, 0, "{}", rendered(&linked));
        recorded_kind(&mut shell, project.path(), "symlink").await
    });
    assert_eq!(
        std::fs::read_link(project.path().join("link"))
            .expect("the link is on the host")
            .to_string_lossy(),
        "file"
    );
    assert_eq!(kind, Some(true));
}

#[test]
fn a_readlink_that_lands_records_a_response_and_charges_the_read_link_budget() {
    let project = project();
    std::os::unix::fs::symlink("file", project.path().join("link")).expect("a host link");
    let mut shell = shell_over(
        project.path(),
        &governed_by(PROJECT_SCOPED, READLINK_PROBES),
    );
    let kind = run(async {
        let read = shell.run("readlink /work/link").await;
        assert_eq!(read.status, 0, "{}", rendered(&read));
        assert_eq!(read.stdout.trim(), "file");
        recorded_kind(&mut shell, project.path(), "readlink").await
    });
    assert_eq!(kind, Some(true));
}

#[test]
fn a_readlink_that_fails_records_an_error_and_charges_nothing() {
    let project = project();
    let mut shell = shell_over(
        project.path(),
        &governed_by(PROJECT_SCOPED, READLINK_PROBES),
    );
    let kind = run(async {
        let read = shell.run("readlink /work/file").await;
        assert_admitted_then_failed(&read);
        assert!(read.stdout.is_empty(), "{}", rendered(&read));
        recorded_kind(&mut shell, project.path(), "readlink").await
    });
    assert_eq!(kind, Some(false));
}

/// A probe write forbidden once at least `threshold` `set_permissions` responses are in history.
fn at_least(threshold: u32) -> String {
    format!(
        r#"
@id("at-least-{threshold}")
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when {{ context.input.path == "/work/probe-at-least-{threshold}" }}
when temporal {{
    exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within 3600s (
                Box::Action::"fs:write"::response{{ input.path: _, input.operation: Box::FsWriteOperation::"set_permissions" }} && tp(t)
            )
        )) == total
        && total >= {threshold}
    )
}};
"#
    )
}

#[test]
fn a_set_permissions_budget_counts_the_chmods_that_landed_and_not_the_one_that_failed() {
    let project = project();
    std::fs::write(project.path().join("other"), "payload").expect("a second file");
    let source = format!("{PROJECT_SCOPED}{}{}", at_least(2), at_least(3));
    let mut shell = shell_over(project.path(), &source);
    let (two, three) = run(async {
        for command in ["chmod 600 /work/file", "chmod 600 /work/other"] {
            let changed = shell.run(command).await;
            assert_eq!(changed.status, 0, "{}", rendered(&changed));
        }
        assert_admitted_then_failed(&shell.run("chmod 600 /work/missing").await);
        (
            probe(&mut shell, project.path(), "at-least-2").await,
            probe(&mut shell, project.path(), "at-least-3").await,
        )
    });
    assert!(two, "two chmods landed, so the budget of two is spent");
    assert!(!three, "the failed chmod is not charged");
}
