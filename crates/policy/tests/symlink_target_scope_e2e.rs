//! A relative symlink target is judged on the path it resolves to, through the hosted Shell on a
//! direct host bind, while the kernel stores the text as spelled.

#![cfg(feature = "shell-adapter")]

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use policy::{GovernedBox, Policy, Principal, ShellPolicyInterceptor};
use strands_shell::{Output, Shell};

/// A Shell over `project`, bound directly at `/work`, governed by `source`.
fn shell_over(project: &Path, source: &str) -> Shell {
    let policy = support::open_policy(vec![Policy {
        origin: PathBuf::from("symlink-target-scope.dw"),
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

/// A project directory that holds two regular files, `file` and `secret`.
fn project() -> tempfile::TempDir {
    let project = tempfile::tempdir().expect("a project directory");
    std::fs::write(project.path().join("file"), "payload").expect("the project file");
    std::fs::write(project.path().join("secret"), "hidden").expect("the project secret");
    project
}

/// `fs:read` and `fs:write` below the project, and nothing else: the policy from issue #151.
const PROJECT_SCOPED: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.path == "/work" || context.input.path like "/work/*" };
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when { context.input.path == "/work" || context.input.path like "/work/*" };
"#;

/// A probe write forbidden once history holds a `fs:write` symlink request on `path`.
fn judged_on(path: &str) -> String {
    format!(
        r#"
@id("judged")
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when {{ context.input.path == "/work/probe-judged" }}
when temporal {{
    formerly within 3600s (
        Box::Action::"fs:write"::request{{ input.path: "{path}", input.operation: Box::FsWriteOperation::"symlink" }}
    )
}};
"#
    )
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

fn link_text(project: &Path) -> String {
    std::fs::read_link(project.join("link"))
        .expect("the link is on the host")
        .to_string_lossy()
        .into_owned()
}

fn no_link(project: &Path) {
    assert!(
        std::fs::symlink_metadata(project.join("link")).is_err(),
        "a refused symlink leaves nothing on the host"
    );
}

#[test]
fn a_relative_symlink_target_is_judged_on_the_path_it_resolves_to() {
    let project = project();
    let source = format!("{PROJECT_SCOPED}{}", judged_on("/work/file"));
    let mut shell = shell_over(project.path(), &source);
    let judged = run(async {
        let linked = shell.run("ln -s file /work/link").await;
        assert_eq!(linked.status, 0, "{}", rendered(&linked));
        probe(&mut shell, project.path(), "judged").await
    });
    assert_eq!(
        link_text(project.path()),
        "file",
        "the stored text is as spelled"
    );
    assert!(judged, "the fs:write symlink request names /work/file");
}

#[test]
fn a_relative_symlink_target_that_escapes_the_project_is_refused() {
    let project = project();
    let mut shell = shell_over(project.path(), PROJECT_SCOPED);
    let linked = run(shell.run("ln -s ../../etc/passwd /work/link"));
    assert_ne!(linked.status, 0, "{}", rendered(&linked));
    assert!(
        linked
            .stderr
            .contains("policy denied this operation on '/etc/passwd' [default-deny]"),
        "{}",
        rendered(&linked)
    );
    no_link(project.path());
}

#[test]
fn a_dangling_relative_symlink_target_is_still_judged_on_its_resolved_path() {
    let project = project();
    let source = format!("{PROJECT_SCOPED}{}", judged_on("/work/missing"));
    let mut shell = shell_over(project.path(), &source);
    let judged = run(async {
        let linked = shell.run("ln -s missing /work/link").await;
        assert_eq!(linked.status, 0, "{}", rendered(&linked));
        probe(&mut shell, project.path(), "judged").await
    });
    assert_eq!(link_text(project.path()), "missing");
    assert!(
        !project.path().join("missing").exists(),
        "the target was never created"
    );
    assert!(judged, "the fs:write symlink request names /work/missing");
}

#[test]
fn a_read_forbid_on_the_resolved_target_still_fences_a_relative_symlink() {
    let project = project();
    let source = format!(
        r#"{PROJECT_SCOPED}
@id("no-secret")
@description("The secret stays unlinked.")
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when {{
    context.input.operation == Box::FsReadOperation::"read_content" &&
    context.input.path == "/work/secret"
}};"#
    );
    let mut shell = shell_over(project.path(), &source);
    let (linked, other) = run(async {
        (
            shell.run("ln -s secret /work/link").await,
            shell.run("ln -s file /work/other").await,
        )
    });
    assert_ne!(linked.status, 0, "{}", rendered(&linked));
    assert!(
        linked.stderr.contains(
            "policy denied this operation on '/work/secret' [policy: no-secret]: The secret stays unlinked."
        ),
        "{}",
        rendered(&linked)
    );
    no_link(project.path());
    assert_eq!(other.status, 0, "{}", rendered(&other));
    assert_eq!(
        std::fs::read_link(project.path().join("other"))
            .expect("the other link is on the host")
            .to_string_lossy(),
        "file"
    );
}

#[test]
fn a_relative_symlink_target_from_a_nested_link_resolves_from_the_links_directory() {
    let project = project();
    std::fs::create_dir(project.path().join("nested")).expect("a nested directory");
    let source = format!("{PROJECT_SCOPED}{}", judged_on("/work/file"));
    let mut shell = shell_over(project.path(), &source);
    let judged = run(async {
        let linked = shell.run("ln -s ../file /work/nested/link").await;
        assert_eq!(linked.status, 0, "{}", rendered(&linked));
        probe(&mut shell, project.path(), "judged").await
    });
    assert_eq!(
        std::fs::read_link(project.path().join("nested/link"))
            .expect("the nested link is on the host")
            .to_string_lossy(),
        "../file"
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("nested/link")).expect("the link resolves"),
        "payload"
    );
    assert!(judged, "the fs:write symlink request names /work/file");
}

/// LIVE GAP, pinned as it stands: on a direct bind the kernel reports a read through a host
/// symlink by the alias spelling, so a link to a directory carries a subtree read forbid away.
#[test]
fn a_directory_symlink_on_a_direct_bind_is_not_defended_by_a_subtree_read_forbid() {
    let project = project();
    std::fs::create_dir(project.path().join("private")).expect("a private directory");
    std::fs::write(project.path().join("private/secret"), "hidden").expect("the private secret");
    let source = format!(
        r#"{PROJECT_SCOPED}
@id("no-private")
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when {{
    context.input.operation == Box::FsReadOperation::"read_content" &&
    context.input.path like "/work/private/*"
}};"#
    );
    let mut shell = shell_over(project.path(), &source);
    let (direct, linked, aliased) = run(async {
        (
            shell.run("cat /work/private/secret").await,
            shell.run("ln -s private /work/sub").await,
            shell.run("cat /work/sub/secret").await,
        )
    });
    assert!(
        direct.stderr.contains("[policy: no-private]"),
        "{}",
        rendered(&direct)
    );
    assert_eq!(linked.status, 0, "{}", rendered(&linked));
    assert_eq!(
        (aliased.status, aliased.stdout.as_str()),
        (0, "hidden"),
        "the alias read is judged on /work/sub/secret, not /work/private/secret: {}",
        rendered(&aliased)
    );
}
