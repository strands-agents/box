//! The kernel effect seam: every effect is admitted individually, not the command.
//!
//! One `shell:run` admission expands into many kernel effects. These tests pin the
//! expansion, the fail-closed behavior of each denial path, and the outcome each
//! operation reports.

mod support;

use std::io;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use box_shell::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, EffectResult, FsOperation,
    FsPairOperation,
};
use strands_shell::Shell;

/// One admitted effect, rendered as a stable string for assertions.
fn render(effect: &EffectAttempt<'_>) -> String {
    match effect {
        EffectAttempt::ShellRun { command, .. } => format!("shell:run {command}"),
        EffectAttempt::Filesystem { path, operation } => {
            let verb = match operation {
                FsOperation::ReadContent => "read".to_string(),
                FsOperation::WriteContent { create, truncate } => {
                    format!("write(create={create},truncate={truncate})")
                }
                FsOperation::ReadMetadata { follow_symlinks } => {
                    format!("meta(follow={follow_symlinks})")
                }
                FsOperation::Enumerate => "enumerate".to_string(),
                FsOperation::Exec => "exec".to_string(),
                FsOperation::Locate => "locate".to_string(),
                FsOperation::RemoveFile => "remove_file".to_string(),
                FsOperation::RemoveDir => "remove_dir".to_string(),
                FsOperation::CreateDir => "create_dir".to_string(),
                FsOperation::SetPermissions { mode } => format!("chmod({mode:o})"),
                FsOperation::ChangeDir => "change_dir".to_string(),
                FsOperation::ReadLink => "read_link".to_string(),
                _ => "other".to_string(),
            };
            format!("{verb} {path}")
        }
        EffectAttempt::FilesystemPair {
            from,
            to,
            operation,
        } => {
            let verb = match operation {
                FsPairOperation::Rename {
                    destination_exists: false,
                    ..
                } => "rename",
                FsPairOperation::Rename {
                    destination_exists: true,
                    destination_is_dir: false,
                } => "rename(destination_exists)",
                FsPairOperation::Rename {
                    destination_exists: true,
                    destination_is_dir: true,
                } => "rename(destination_exists,dir)",
                FsPairOperation::Symlink => "symlink",
                _ => "pair",
            };
            format!("{verb} {from} -> {to}")
        }
        // No network variant: the Shell raises no request or credential attempt.
        _ => "unknown".to_string(),
    }
}

/// Records every admission and denies whatever a test asks it to.
struct Recorder {
    attempted: Mutex<Vec<String>>,
    admitted: Arc<Mutex<Vec<String>>>,
    outcomes: Arc<Mutex<Vec<(String, EffectResult)>>>,
    deny: Box<dyn Fn(&str) -> bool + Send + Sync>,
}

impl Recorder {
    fn allowing_everything() -> (Arc<Self>, Arc<Mutex<Vec<String>>>) {
        Self::denying(|_| false)
    }

    fn denying<F>(deny: F) -> (Arc<Self>, Arc<Mutex<Vec<String>>>)
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        let admitted = Arc::new(Mutex::new(Vec::new()));
        let interceptor = Arc::new(Self {
            attempted: Mutex::new(Vec::new()),
            admitted: Arc::clone(&admitted),
            outcomes: Arc::new(Mutex::new(Vec::new())),
            deny: Box::new(deny),
        });
        (interceptor, admitted)
    }

    /// A recorder whose denial only takes effect once `armed` is set.
    fn armable<F>(deny: F) -> (Arc<Self>, Arc<Mutex<Vec<String>>>, Arc<AtomicBool>)
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        let armed = Arc::new(AtomicBool::new(false));
        let gate = Arc::clone(&armed);
        let (interceptor, admitted) =
            Self::denying(move |effect| gate.load(Ordering::SeqCst) && deny(effect));
        (interceptor, admitted, armed)
    }
}

#[async_trait]
impl EffectInterceptor for Recorder {
    async fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let rendered = render(effect);
        self.attempted.lock().unwrap().push(rendered.clone());
        if (self.deny)(&rendered) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("test policy denied: {rendered}"),
            ));
        }
        self.admitted.lock().unwrap().push(rendered.clone());
        Ok(Box::new(RecordingPermit {
            effect: rendered,
            outcomes: Arc::clone(&self.outcomes),
        }))
    }
}

struct RecordingPermit {
    effect: String,
    outcomes: Arc<Mutex<Vec<(String, EffectResult)>>>,
}

#[async_trait]
impl EffectPermit for RecordingPermit {
    async fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        if let EffectOutcome::Kernel(result) = outcome {
            self.outcomes.lock().unwrap().push((self.effect, result));
        }
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {
        self.outcomes
            .lock()
            .unwrap()
            .push((self.effect, EffectResult::Indeterminate));
    }
}

/// Run `body` on a current-thread runtime inside a `LocalSet`, as the VFS requires.
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

fn shell_with(interceptor: Arc<dyn EffectInterceptor>) -> Shell {
    support::builder()
        .effect_interceptor(interceptor)
        .build()
        .expect("shell builds")
}

/// The headline property: one admission per **resolved command**, many individually-admitted
/// effects underneath each.
#[test]
fn one_command_admission_expands_into_individual_effect_admissions() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);

    run(async {
        let setup = shell
            .run("mkdir -p /home/lash/w && printf 'AAA\\n' > /home/lash/w/a.txt")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        admitted.lock().unwrap().clear();

        let out = shell
            .run(
                "mkdir -p /home/lash/w/out && for f in /home/lash/w/*.txt; do \
                 cat $f >> /home/lash/w/out/all.log; done; \
                 cp /home/lash/w/out/all.log /home/lash/w/out/copy.log && \
                 rm /home/lash/w/out/all.log",
            )
            .await;
        assert_eq!(out.status, 0, "payload: {}", out.stderr);
    });

    let seen = admitted.lock().unwrap().clone();

    // One command-level admission per resolved program the payload runs, and each names
    // that program rather than the submitted line.
    let commands: Vec<_> = seen.iter().filter(|e| e.starts_with("shell:run")).collect();
    for program in ["mkdir", "cat", "cp", "rm"] {
        assert!(
            commands
                .iter()
                .any(|entry| entry.starts_with(&format!("shell:run {program} "))),
            "expected a decision naming `{program}`, saw {commands:?}"
        );
    }
    assert!(
        commands.len() >= 4,
        "one decision per resolved command, saw {commands:?}"
    );

    // ...and many effect-level admissions underneath it.
    let effects: Vec<_> = seen
        .iter()
        .filter(|e| !e.starts_with("shell:run"))
        .cloned()
        .collect();
    assert!(
        effects.len() > 10,
        "expected the command to expand into many effects, saw {} — {effects:?}",
        effects.len()
    );

    // Each distinct effect class the payload causes is individually visible.
    let has = |needle: &str| effects.iter().any(|e| e.contains(needle));
    assert!(has("create_dir /home/lash/w/out"), "mkdir: {effects:?}");
    // The *directory* is enumerated, not the pattern: a pattern is not a path, so a
    // path rule could not meaningfully match one.
    assert!(has("enumerate /home/lash/w"), "glob scope: {effects:?}");
    assert!(
        !has("enumerate /home/lash/w/*.txt"),
        "a glob pattern must never be authorized as a path: {effects:?}"
    );
    assert!(has("read /home/lash/w/a.txt"), "cat source: {effects:?}");
    assert!(
        has("write(create=true,truncate=false) /home/lash/w/out/all.log"),
        "append open: {effects:?}"
    );
    assert!(
        has("read /home/lash/w/out/all.log"),
        "cp source: {effects:?}"
    );
    assert!(
        has("write(create=true,truncate=true) /home/lash/w/out/copy.log"),
        "cp dest: {effects:?}"
    );
    assert!(
        has("meta(follow=false) /home/lash/w/out/all.log"),
        "no-follow probe before delete: {effects:?}"
    );
    assert!(
        has("remove_file /home/lash/w/out/all.log"),
        "rm: {effects:?}"
    );
}

/// Paths are admitted resolved, not as the caller spelled them.
#[test]
fn admitted_paths_are_resolved_not_caller_spelled() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);

    run(async {
        let out = shell
            .run("mkdir -p /home/lash/deep && cd /home/lash/deep && cat ../../lash/deep/../deep/x 2>/dev/null; true")
            .await;
        assert_eq!(out.status, 0, "{}", out.stderr);
    });

    let seen = admitted.lock().unwrap().clone();
    assert!(
        seen.iter().any(|e| e.contains("/home/lash/deep/x")),
        "relative and dot-segment spellings must resolve before admission: {seen:?}"
    );
    // The raw spelling survives only in the command-level admission, which is
    // by definition the unparsed text. No *effect* admission carries a dot segment.
    let effects: Vec<_> = seen
        .iter()
        .filter(|e| !e.starts_with("shell:run"))
        .collect();
    assert!(
        !effects.iter().any(|e| e.contains("..")),
        "no effect admission may carry an unresolved dot segment: {effects:?}"
    );
}

/// Builds `private/sub/file` and `open/sub/file` under `/home/lash/t`, then refuses to
/// enumerate `/home/lash/t/private`.
fn shell_with_a_private_directory() -> (Shell, Arc<Recorder>, usize) {
    let (interceptor, _, armed) =
        Recorder::armable(|effect| effect == "enumerate /home/lash/t/private");
    let mut shell = shell_with(interceptor.clone());
    let setup_attempts = run(async {
        let setup = shell
            .run(
                "mkdir -p /home/lash/t/private/sub /home/lash/t/open/sub && \
                 printf 'x' > /home/lash/t/private/sub/file && \
                 printf 'x' > /home/lash/t/open/sub/file",
            )
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        interceptor.attempted.lock().unwrap().len()
    });
    armed.store(true, Ordering::SeqCst);
    (shell, interceptor, setup_attempts)
}

/// A wildcard above the parent of a match reads a directory the parent check does not name.
#[test]
fn three_wildcard_levels_enumerate_no_refused_intermediate_directory() {
    let (mut shell, interceptor, setup_attempts) = shell_with_a_private_directory();

    let out = run(async { shell.run("echo /home/lash/t/*/*/*").await });

    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(out.stdout.trim(), "/home/lash/t/open/sub/file");
    let enumerated = interceptor.attempted.lock().unwrap()[setup_attempts..]
        .iter()
        .filter(|effect| effect.starts_with("enumerate "))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        enumerated,
        [
            "enumerate /home/lash/t",
            "enumerate /home/lash/t/open",
            "enumerate /home/lash/t/open/sub",
            "enumerate /home/lash/t/private",
        ],
        "each directory is asked once, and none below a refused one"
    );
    let below_the_refusal = interceptor.attempted.lock().unwrap()[setup_attempts..]
        .iter()
        .filter(|effect| effect.contains(" /home/lash/t/private/"))
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        below_the_refusal.is_empty(),
        "no effect reaches a path below the refused directory: {below_the_refusal:?}"
    );
}

/// Two wildcard levels drop a match whose parent is refused.
#[test]
fn two_wildcard_levels_drop_a_match_in_a_refused_directory() {
    let (mut shell, _, _) = shell_with_a_private_directory();

    let out = run(async { shell.run("echo /home/lash/t/*/*").await });

    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(out.stdout.trim(), "/home/lash/t/open/sub");
}

/// A relative pattern enumerates the working directory, not `/`.
#[test]
fn a_relative_glob_enumerates_the_working_directory() {
    let (mut shell, _, _) = shell_with_a_private_directory();

    let (inside, below) = run(async {
        let inside = shell.run("cd /home/lash/t/private && echo *").await;
        let below = shell.run("cd /home/lash/t && echo */*/*").await;
        (inside, below)
    });

    assert_eq!(inside.stdout.trim(), "*", "{}", inside.stderr);
    assert_eq!(below.stdout.trim(), "open/sub/file", "{}", below.stderr);
}

/// The enumeration decisions for a wide tree are one for each distinct directory read.
#[test]
fn glob_enumeration_decisions_are_one_for_each_directory_read() {
    let (interceptor, _) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor.clone());

    let (out, setup_attempts) = run(async {
        let setup = shell
            .run(
                "for a in a b c; do for b in x y; do mkdir -p /home/lash/w/$a/$b; \
                 for f in 1 2 3; do printf 'x' > /home/lash/w/$a/$b/$f; done; done; done",
            )
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        let setup_attempts = interceptor.attempted.lock().unwrap().len();
        (shell.run("echo /home/lash/w/*/*/*").await, setup_attempts)
    });

    assert_eq!(out.stdout.split_whitespace().count(), 18, "{}", out.stderr);
    let mut enumerated = interceptor.attempted.lock().unwrap()[setup_attempts..]
        .iter()
        .filter(|effect| effect.starts_with("enumerate "))
        .cloned()
        .collect::<Vec<_>>();
    let decisions = enumerated.len();
    enumerated.sort();
    enumerated.dedup();
    assert_eq!(decisions, enumerated.len(), "{enumerated:?}");
    assert_eq!(decisions, 1 + 3 + 6, "{enumerated:?}");
}

/// A denied metadata probe reports "not found" rather than surfacing an error.
#[test]
fn denying_metadata_reports_absent_rather_than_leaking() {
    let (interceptor, _) = Recorder::denying(|e| e.starts_with("meta("));
    let mut shell = shell_with(interceptor);

    let out = run(async {
        let setup = shell.run("printf 'secret' > /home/lash/hidden.txt").await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        shell
            .run("test -e /home/lash/hidden.txt && echo FOUND || echo ABSENT")
            .await
    });

    assert!(
        out.stdout.contains("ABSENT"),
        "a denied metadata probe must read as absent: {:?} / {:?}",
        out.stdout,
        out.stderr
    );
}

/// The file API bypassed the old seam entirely; it is mediated now.
#[test]
fn the_direct_file_api_is_mediated() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);

    run(async {
        shell
            .write_file("/home/lash/api.txt", b"payload")
            .await
            .expect("write succeeds");
        shell
            .read_file("/home/lash/api.txt")
            .await
            .expect("read succeeds");
        shell.list_files("/home/lash").await.expect("list succeeds");
        shell
            .remove_file("/home/lash/api.txt")
            .await
            .expect("remove succeeds");
    });

    let seen = admitted.lock().unwrap().clone();
    assert!(
        !seen.iter().any(|e| e.starts_with("shell:run")),
        "the file API submits no command: {seen:?}"
    );
    for expected in [
        "write(create=true,truncate=true) /home/lash/api.txt",
        "read /home/lash/api.txt",
        "enumerate /home/lash",
        "remove_file /home/lash/api.txt",
    ] {
        assert!(
            seen.iter().any(|e| e == expected),
            "the file API must admit {expected:?}: {seen:?}"
        );
    }
}

/// Denying a read through the direct API fails it closed.
#[test]
fn denying_a_direct_api_read_fails_it_closed() {
    let (interceptor, _) = Recorder::denying(|e| e.starts_with("read "));
    let mut shell = shell_with(interceptor);

    let result = run(async {
        shell
            .write_file("/home/lash/api.txt", b"payload")
            .await
            .expect("write is allowed");
        shell.read_file("/home/lash/api.txt").await
    });

    let error = result.expect_err("a denied read must fail");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

/// An open reports a descriptor, never a completed transfer.
#[test]
fn an_open_reports_a_descriptor_not_a_transfer() {
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let interceptor = Arc::new(Recorder {
        attempted: Mutex::new(Vec::new()),
        admitted: Arc::new(Mutex::new(Vec::new())),
        outcomes: Arc::clone(&outcomes),
        deny: Box::new(|_| false),
    });
    let mut shell = shell_with(interceptor);

    run(async {
        shell
            .write_file("/home/lash/o.txt", b"bytes")
            .await
            .expect("write succeeds");
        shell
            .read_file("/home/lash/o.txt")
            .await
            .expect("read succeeds");
    });

    let recorded = outcomes.lock().unwrap().clone();
    let opens: Vec<_> = recorded
        .iter()
        .filter(|(effect, _)| effect.starts_with("read ") || effect.starts_with("write("))
        .collect();
    assert!(
        !opens.is_empty(),
        "opens must report an outcome: {recorded:?}"
    );
    for (effect, result) in opens {
        assert_eq!(
            *result,
            EffectResult::DescriptorIssued,
            "{effect} must report DescriptorIssued, not a transfer"
        );
    }

    // A one-shot operation, by contrast, completes within its call.
    let one_shot = recorded
        .iter()
        .find(|(effect, _)| effect.starts_with("create_dir") || effect.starts_with("enumerate"));
    if let Some((effect, result)) = one_shot {
        assert_eq!(
            *result,
            EffectResult::Completed,
            "{effect} completes within its call"
        );
    }
}

/// An answered metadata probe reports a completed effect, whether the answer is yes or no.
#[test]
fn an_answered_probe_reports_a_completed_effect() {
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let interceptor = Arc::new(Recorder {
        attempted: Mutex::new(Vec::new()),
        admitted: Arc::new(Mutex::new(Vec::new())),
        outcomes: Arc::clone(&outcomes),
        deny: Box::new(|_| false),
    });
    let mut shell = shell_with(interceptor);

    let out = run(async {
        shell
            .run(
                "printf x > /home/lash/present; test -e /home/lash/present; echo $?; \
                 test -e /home/lash/absent; echo $?; test -r /home/lash/absent; echo $?; \
                 test -L /home/lash/absent; echo $?",
            )
            .await
    });
    assert_eq!(out.stdout, "0\n1\n1\n1\n", "{}", out.stderr);

    let recorded = outcomes.lock().unwrap().clone();
    let probes: Vec<_> = recorded
        .iter()
        .filter(|(effect, _)| {
            effect.starts_with("meta(")
                && (effect.ends_with("/home/lash/present") || effect.ends_with("/home/lash/absent"))
        })
        .collect();
    assert!(
        probes
            .iter()
            .any(|(effect, _)| effect == "meta(follow=false) /home/lash/absent"),
        "the absent-path lstat must report an outcome: {recorded:?}"
    );
    for (effect, result) in probes {
        assert_eq!(*result, EffectResult::Completed, "{effect}");
    }
}

/// A metadata probe that the admission-window guard refuses reports a failure, not an answer.
#[test]
fn a_probe_the_admission_window_refuses_reports_a_failure() {
    struct Slow {
        inner: Arc<Recorder>,
    }

    #[async_trait]
    impl EffectInterceptor for Slow {
        async fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            self.inner.intercept(effect).await
        }
    }

    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::new(Recorder {
        attempted: Mutex::new(Vec::new()),
        admitted: Arc::new(Mutex::new(Vec::new())),
        outcomes: Arc::clone(&outcomes),
        deny: Box::new(|_| false),
    });
    let mut shell = support::builder()
        .effect_interceptor(Arc::new(Slow { inner: recorder }))
        .build()
        .expect("shell builds");

    let out = run(async {
        let setup = shell
            .run("printf x > /home/lash/present && ln -s present /home/lash/link")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        outcomes.lock().unwrap().clear();
        shell
            .run(
                "for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do mkdir /home/lash/churn; rmdir /home/lash/churn; done & \\
                 for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do test -e /home/lash/present; echo e$?; test -L /home/lash/link; echo l$?; test -r /home/lash/present; echo r$?; done; wait",
            )
            .await
    });

    let recorded = outcomes.lock().unwrap().clone();
    let completed = |effect: &str| {
        recorded
            .iter()
            .filter(|(seen, result)| seen == effect && *result == EffectResult::Completed)
            .count()
    };
    let yes = |tag: &str| {
        out.stdout
            .lines()
            .filter(|line| *line == format!("{tag}0"))
            .count()
    };
    assert_eq!(
        completed("meta(follow=true) /home/lash/present"),
        yes("e") + yes("r"),
        "only a stat or access that answered may report completed: {:?}",
        out.stdout
    );
    assert_eq!(
        completed("meta(follow=false) /home/lash/link"),
        yes("l"),
        "only an lstat that answered may report completed: {:?}",
        out.stdout
    );
    assert!(
        yes("e") + yes("l") + yes("r") < 60,
        "the namespace churn must refuse at least one probe: {:?}",
        out.stdout
    );
}

/// A read-write open (`<>`) needs the read authorization too.
#[test]
fn a_read_write_open_requires_read_authorization() {
    let (interceptor, _) = Recorder::denying(|e| e.starts_with("read /home/lash/secret.txt"));
    let mut shell = shell_with(interceptor);

    let out = run(async {
        let setup = shell
            .run("printf 'TOPSECRET' > /home/lash/secret.txt")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        shell.run("cat <> /home/lash/secret.txt").await
    });

    assert!(
        !out.stdout.contains("TOPSECRET"),
        "a read-write open must not disclose content under a write-only permit: {:?}",
        out.stdout
    );
}

/// A no-follow operation is admitted on the link, not on its target.
#[test]
fn no_follow_operations_are_admitted_on_the_link_itself() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);

    run(async {
        let setup = shell
            .run("printf 'target' > /home/lash/real && ln -s /home/lash/real /home/lash/link")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        admitted.lock().unwrap().clear();
        let removed = shell.run("rm /home/lash/link").await;
        assert_eq!(removed.status, 0, "rm: {}", removed.stderr);
    });

    let seen = admitted.lock().unwrap().clone();
    assert!(
        seen.iter().any(|e| e == "remove_file /home/lash/link"),
        "unlink must be admitted on the link it removes: {seen:?}"
    );
    assert!(
        !seen.iter().any(|e| e == "remove_file /home/lash/real"),
        "unlink must not be admitted against the link's target: {seen:?}"
    );
}

/// A rename reports whether its destination exists, read from the resolved destination.
#[test]
fn a_rename_reports_whether_its_destination_exists() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);

    let (replaced, target) = run(async {
        let setup = shell
            .run(
                "printf 'payload' > /home/lash/a && printf 'original' > /home/lash/b \
                 && printf 'second' > /home/lash/d && ln -s /home/lash/c /home/lash/link \
                 && printf 'third' > /home/lash/e && ln -s /home/lash/nowhere /home/lash/dangling \
                 && mkdir /home/lash/dir1 /home/lash/dir2",
            )
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        admitted.lock().unwrap().clear();
        let onto_dangling = shell.run("mv /home/lash/e /home/lash/dangling").await;
        assert_eq!(
            onto_dangling.status, 0,
            "mv onto a dangling link: {}",
            onto_dangling.stderr
        );
        let _ = shell
            .run(r#"lua -e "os.rename([[/home/lash/dir1]],[[/home/lash/dir2]])""#)
            .await;
        let onto_existing = shell.run("mv /home/lash/a /home/lash/b").await;
        assert_eq!(
            onto_existing.status, 0,
            "mv onto a file: {}",
            onto_existing.stderr
        );
        let onto_absent = shell.run("mv /home/lash/b /home/lash/c").await;
        assert_eq!(
            onto_absent.status, 0,
            "mv onto a new name: {}",
            onto_absent.stderr
        );
        let onto_link = shell.run("mv /home/lash/d /home/lash/link").await;
        assert_eq!(onto_link.status, 0, "mv onto a link: {}", onto_link.stderr);
        let replaced = shell.run("cat /home/lash/link").await;
        let target = shell.run("cat /home/lash/c").await;
        (replaced, target)
    });

    let seen = admitted.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|e| e == "rename(destination_exists) /home/lash/a -> /home/lash/b"),
        "a rename onto an existing file reports that the destination exists: {seen:?}"
    );
    assert!(
        seen.iter()
            .any(|e| e == "rename /home/lash/b -> /home/lash/c"),
        "a rename onto an absent name reports no existing destination: {seen:?}"
    );
    assert!(
        seen.iter()
            .any(|e| e == "rename(destination_exists) /home/lash/d -> /home/lash/link"),
        "a live symlink at the destination is the name the rename replaces: {seen:?}"
    );
    assert!(
        seen.iter()
            .any(|e| e == "rename(destination_exists) /home/lash/e -> /home/lash/dangling"),
        "a dangling symlink is a bound name, so the destination exists: {seen:?}"
    );
    assert!(
        seen.iter()
            .any(|e| e == "rename(destination_exists,dir) /home/lash/dir1 -> /home/lash/dir2"),
        "a directory destination reports that it is a directory: {seen:?}"
    );
    assert_eq!(
        replaced.stdout, "second",
        "the last rename replaced the link with the file"
    );
    assert_eq!(
        target.stdout, "payload",
        "the link's old target is untouched"
    );
}

/// No *effect* attempt carries a request URL, so none can leak its query.
#[test]
fn no_effect_attempt_carries_a_request_url() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = support::builder()
        .effect_interceptor(interceptor)
        .build()
        .expect("shell builds");

    run(async {
        shell
            .run("curl -s 'https://q.example.com/v1/thing?apikey=SUPERSECRET-QUERY'")
            .await
    });

    let effects: Vec<_> = admitted
        .lock()
        .unwrap()
        .iter()
        .filter(|e| !e.starts_with("shell:run"))
        .cloned()
        .collect();
    assert!(
        !effects.iter().any(|e| e.contains("SUPERSECRET-QUERY")),
        "no effect admission may carry query material: {effects:?}"
    );
    assert!(
        !effects.iter().any(|e| e.contains("q.example.com")),
        "the Shell must raise no network attempt: {effects:?}"
    );
}

// Removed with the `HttpTransport` seam: `a_disabled_network_never_reaches_the_transport`,
// `the_ssrf_floor_runs_before_the_transport`, and
// `a_request_is_carried_by_the_transport_and_raises_no_attempt`.
//
// All three needed a supplied transport to observe egress without a live network dial.
// The Shell no longer has that seam — routing egress through a boundary is the box's job
// via containment, not a trait the Shell offers. What remains testable here is that no
// effect attempt carries a request URL, which
// `no_effect_attempt_carries_a_request_url` covers.
//
// COVERAGE LOST, stated rather than hidden: nothing in this crate now proves the SSRF
// floor runs before dispatch. The floor is still there (`check_url`, required), and
// `curl_integration.rs` exercises it, but the "floor precedes transport" ordering has no
// test because there is no transport to order against.

/// `mkdir -p` accepts a `.` or `..` component after a component it created.
#[test]
fn mkdir_p_accepts_a_dot_component_after_a_created_one() {
    let (interceptor, _admitted) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);
    let (made, listing) = run(async {
        let made = shell
            .run("mkdir -p /home/lash/x/new/../sib && mkdir -p /home/lash/y/b/.")
            .await;
        let listing = shell.run("ls /home/lash/x /home/lash/y").await;
        (made, listing)
    });
    assert_eq!(made.status, 0, "{}", made.stderr);
    assert_eq!(
        listing.stdout.split_whitespace().collect::<Vec<_>>(),
        ["/home/lash/x:", "new", "sib", "/home/lash/y:", "b"],
        "{}",
        listing.stderr
    );
}

/// A chain of dangling symlinks longer than the kernel follows is no existence oracle either.
#[test]
fn a_long_symlink_chain_is_no_existence_oracle() {
    for links in [40, 42] {
        let (interceptor, _) = Recorder::denying(|e| {
            e.starts_with("change_dir ")
                && !e.starts_with("change_dir /tmp")
                && !e.starts_with("change_dir /home/lash")
        });
        let mut shell = shell_with(interceptor);
        let chain = |dir: &str, target: &str| {
            let mut setup = format!("mkdir -p /tmp/{dir}");
            for hop in 1..links {
                setup.push_str(&format!(
                    " && ln -s /tmp/{dir}/l{} /tmp/{dir}/l{hop}",
                    hop + 1
                ));
            }
            setup.push_str(&format!(" && ln -s {target} /tmp/{dir}/l{links}"));
            setup
        };

        let (present, missing) = run(async {
            for setup in [
                chain("present", "/usr"),
                chain("missing", "/nonexistent_probe"),
            ] {
                let out = shell.run(&setup).await;
                assert_eq!(out.status, 0, "setup: {}", out.stderr);
            }
            (
                shell.run("cd /tmp/present/l1/x").await,
                shell.run("cd /tmp/missing/l1/x").await,
            )
        });

        assert_ne!(present.status, 0, "{links} links: {}", present.stderr);
        assert_eq!(
            present
                .stderr
                .replace("present", "CHAIN")
                .replace("/usr", "TARGET"),
            missing
                .stderr
                .replace("missing", "CHAIN")
                .replace("/nonexistent_probe", "TARGET"),
            "{links} links: the error does not show whether the chain's target exists"
        );
    }
}

/// `mkdir` and `mv` act on a symlink at the final component, whether or not its target exists.
#[test]
fn mkdir_and_mv_act_on_a_final_symlink_itself() {
    let (interceptor, admitted) = Recorder::denying(|e| {
        !e.starts_with("shell:run") && !e.starts_with("symlink") && e.contains(" /usr")
    });
    let mut shell = shell_with(interceptor);

    let (present, missing, moved, target) = run(async {
        let setup = shell
            .run(
                "mkdir -p /tmp/probes && ln -s /usr /tmp/probes/present \
                 && ln -s /tmp/made /tmp/probes/missing && printf 'data' > /tmp/payload",
            )
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        let present = shell.run("mkdir /tmp/probes/present").await;
        let missing = shell.run("mkdir /tmp/probes/missing").await;
        let moved = shell.run("mv /tmp/payload /tmp/probes/missing").await;
        let target = shell.run("cat /tmp/made").await;
        (present, missing, moved, target)
    });

    assert_ne!(present.status, 0, "mkdir onto a live link fails");
    assert_ne!(missing.status, 0, "mkdir onto a dangling link fails");
    assert_eq!(
        present.stderr.replace("present", "LINK"),
        missing.stderr.replace("missing", "LINK"),
        "the error does not show whether the target exists"
    );
    assert_eq!(moved.status, 0, "mv replaces the link: {}", moved.stderr);
    assert_ne!(
        target.status, 0,
        "neither mkdir nor mv creates the link's target"
    );
    let seen = admitted.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|e| e == "rename(destination_exists) /tmp/payload -> /tmp/probes/missing"),
        "the rename is judged on the link it replaces: {seen:?}"
    );
}

/// A namespace change between admission and the effect fails closed.
#[test]
fn a_background_symlink_swap_cannot_beat_the_admission_window() {
    struct Slow {
        inner: Arc<Recorder>,
    }

    #[async_trait]
    impl EffectInterceptor for Slow {
        async fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
            // Long enough to be interleaved with by a background job.
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            self.inner.intercept(effect).await
        }
    }

    let (recorder, _admitted, armed) =
        Recorder::armable(|e| !e.starts_with("shell:run") && e.contains("/home/lash/sealed/"));
    let mut shell = support::builder()
        .effect_interceptor(Arc::new(Slow { inner: recorder }))
        .build()
        .expect("shell builds");

    let content = run(async {
        let setup = shell
            .run(
                "mkdir -p /home/lash/sealed /home/lash/decoy \
                 && printf 'original' > /home/lash/sealed/f \
                 && ln -s /home/lash/decoy /home/lash/swing",
            )
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        armed.store(true, Ordering::SeqCst);

        // Re-point the alias at the protected directory while writes run through it.
        shell
            .run(
                "for i in 1 2 3 4 5 6 7 8; do \
                   rm -f /home/lash/swing; ln -s /home/lash/sealed /home/lash/swing; \
                   rm -f /home/lash/swing; ln -s /home/lash/decoy /home/lash/swing; \
                 done & \
                 for i in 1 2 3 4 5 6 7 8; do \
                   printf 'PWNED' > /home/lash/swing/f; \
                 done; wait",
            )
            .await;

        armed.store(false, Ordering::SeqCst);
        shell.run("cat /home/lash/sealed/f").await
    });

    assert_eq!(
        content.stdout, "original",
        "a symlink swap inside the admission window must not place content in the \
         protected subtree"
    );
}

/// A protected host source cannot replace the decoy after identity approval.
#[cfg(unix)]
#[test]
fn a_protected_source_cannot_be_swapped_after_identity_approval() {
    struct SourceFloor {
        root: std::path::PathBuf,
        source_device: u64,
        source_inode: u64,
    }

    #[async_trait]
    impl EffectInterceptor for SourceFloor {
        async fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
            if let EffectAttempt::Filesystem {
                path,
                operation: FsOperation::WriteContent { .. },
            } = effect
                && let Ok(relative) = std::path::Path::new(path).strip_prefix("/workspace")
                && let Ok(target) = self.root.join(relative).canonicalize()
                && let Ok(metadata) = std::fs::metadata(target)
                && metadata.dev() == self.source_device
                && metadata.ino() == self.source_inode
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "protected source",
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            Ok(Box::new(NoopPermit))
        }
    }

    struct NoopPermit;

    #[async_trait]
    impl EffectPermit for NoopPermit {
        async fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
            Ok(())
        }

        fn mark_indeterminate(self: Box<Self>) {}
    }

    let directory =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("protected-source-race");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("host bind");
    let source = directory.join("source");
    let decoy = directory.join("decoy");
    let swing = directory.join("swing");
    std::fs::write(&source, "original").expect("protected source");
    std::fs::write(&decoy, "decoy").expect("decoy");
    std::os::unix::fs::symlink("decoy", &swing).expect("initial symlink");
    let source_metadata = std::fs::metadata(&source).expect("source identity");
    let mut shell = support::builder()
        .bind_direct(directory.to_str().expect("UTF-8 host bind"), "/workspace")
        .effect_interceptor(Arc::new(SourceFloor {
            root: directory,
            source_device: source_metadata.dev(),
            source_inode: source_metadata.ino(),
        }))
        .build()
        .expect("shell builds");
    shell.proc.cwd = std::path::PathBuf::from("/workspace");

    run(async {
        shell
            .run(
                "for i in 1 2 3 4; do \
                   rm -f swing; ln -s source swing; \
                   rm -f swing; ln -s decoy swing; \
                 done & \
                 for i in 1 2 3 4; do printf PWNED > swing; done; wait",
            )
            .await
    });

    assert_eq!(
        std::fs::read_to_string(source).expect("protected source reads"),
        "original"
    );
}

#[cfg(unix)]
#[test]
fn a_deferred_host_write_stays_on_the_admitted_inode() {
    use strands_shell::os::Kernel as _;
    use tokio::io::AsyncWriteExt as _;

    let directory = tempfile::tempdir().expect("host folder");
    let directory = directory.path().to_path_buf();
    let source = directory.join("source");
    let decoy = directory.join("decoy");
    let admitted = directory.join("admitted");
    std::fs::write(&source, "original").expect("protected source");
    std::fs::write(&decoy, "decoy").expect("decoy");
    let vfs = strands_shell::vfs_config::build_vfs(&Default::default()).expect("vfs builds");
    let served = directory.to_str().expect("UTF-8").to_string();
    let filesystem =
        Arc::new(box_shell::Filesystem::serving(vfs, &[(&served, "/workspace")]).expect("serves"));
    let kernel = box_shell::ShellKernel::over(filesystem, Arc::new(support::PermitAll));
    let mut proc = kernel.new_process();
    proc.cwd = std::path::PathBuf::from("/workspace");

    run(async {
        let fd = kernel
            .open(&mut proc, "decoy", strands_shell::os::OpenFlags::write())
            .await
            .expect("the decoy opens");

        std::fs::rename(&decoy, &admitted).expect("move the admitted inode");
        std::fs::hard_link(&source, &decoy).expect("replace the pathname with the protected inode");
        let mut writer = proc.take_writer(fd).expect("writer");
        writer.write_all(b"PWNED").await.expect("write");
        drop(writer);
        tokio::task::yield_now().await;
    });

    assert_eq!(
        std::fs::read_to_string(&source).expect("protected source reads"),
        "original"
    );
    assert_eq!(
        std::fs::read_to_string(&decoy).expect("replacement reads"),
        "original"
    );
    assert_eq!(
        std::fs::read_to_string(&admitted).expect("admitted inode reads"),
        "PWNED"
    );
}

/// A substitution's inner text is admitted as its own event, matched **exactly**.
#[test]
fn command_substitution_is_admitted_as_its_own_event() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);

    run(async {
        // (payload, the exact admission entry the inner substitution must produce)
        for (payload, inner) in [
            (
                "X=$(printf SUBSTITUTED); printf %s \"$X\"",
                "shell:run printf SUBSTITUTED",
            ),
            (
                "X=`printf BACKTICKED`; printf %s \"$X\"",
                "shell:run printf BACKTICKED",
            ),
            // Inside a here-doc body, which expands through the same `WordPart` path.
            (
                "cat <<EOF\n$(printf IN_HEREDOC)\nEOF",
                "shell:run printf IN_HEREDOC",
            ),
        ] {
            admitted.lock().unwrap().clear();
            let out = shell.run(payload).await;
            assert_eq!(out.status, 0, "{payload} failed: {}", out.stderr);

            let seen = admitted.lock().unwrap().clone();
            assert!(
                seen.iter().any(|entry| entry == inner),
                "the substitution must be admitted as its own event, exactly {inner:?}; \
                 a `contains` match here would pass on the outer command's entry and prove \
                 nothing. admitted: {seen:?}"
            );
        }
    });
}

/// A refused substitution does not run — and it is refused on what it **expands to**.
#[test]
fn a_denied_command_substitution_does_not_run() {
    // Deny the EXPANDED form. Nothing in the submitted line contains this string, so a seam
    // judging the submission or the substitution's source text would let it through.
    let (interceptor, _admitted) =
        Recorder::denying(|effect| effect == "shell:run printf LAUNDERED_SUB");
    let mut shell = shell_with(interceptor);

    run(async {
        let out = shell
            .run("W=LAUND; X=ERED_SUB; OUT=$(printf \"${W}${X}\"); printf %s \"$OUT\"")
            .await;
        assert!(
            !out.stdout.contains("LAUNDERED"),
            "a refused substitution must not execute; produced {:?}",
            out.stdout
        );
    });
}

/// N substitutions in one submission produce N admissions, not one.
#[test]
fn substitution_fan_out_is_counted_like_every_other_route() {
    fn exec_events(payload: &str) -> usize {
        let (interceptor, admitted) = Recorder::allowing_everything();
        let mut shell = shell_with(interceptor);
        run(async {
            shell.run("printf 'printf y' > /tmp/fan.sh").await;
            admitted.lock().unwrap().clear();
            let out = shell.run(payload).await;
            assert_eq!(out.status, 0, "{payload} failed: {}", out.stderr);
        });
        admitted
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.starts_with("shell:run "))
            .count()
    }

    const LOOP: &str = "for i in 1 2 3 4 5 6 7 8 9 10; do";
    let via_eval = exec_events(&format!("{LOOP} eval printf y; done"));
    let via_source = exec_events(&format!("{LOOP} . /tmp/fan.sh; done"));
    let via_substitution = exec_events(&format!("{LOOP} X=$(printf y); done"));

    // One event per resolved command, and the submission is not one.
    assert_eq!(
        via_eval, 10,
        "baseline: eval should emit one event per body"
    );
    assert_eq!(via_source, 10, "baseline: source should emit one per body");
    assert_eq!(
        via_substitution, via_eval,
        "ten substitutions must cost the same number of shell:run events as ten evals; \
         a lower count means a temporal rule counting shell:run under-counts \
         substitution-driven fan-out"
    );
}

/// One `Output`, rendered for an assertion message.
fn rendered(out: &strands_shell::Output) -> String {
    format!(
        "status={} stdout={:?} stderr={:?}",
        out.status, out.stdout, out.stderr
    )
}

// ── PATH resolution is one decision ──────────────────────────────────────────────────────────

/// Three `PATH` entries, and a script named `tool` under the ones `holding` names.
fn shell_on_three_entries(interceptor: Arc<dyn EffectInterceptor>, holding: &[&str]) -> Shell {
    let mut shell = support::builder()
        .effect_interceptor(interceptor)
        .env("PATH", "/home/lash/one:/home/lash/two:/home/lash/three")
        .build()
        .expect("shell builds");
    run(async {
        for entry in ["one", "two", "three"] {
            let made = shell.run(&format!("mkdir -p /home/lash/{entry}")).await;
            assert_eq!(made.status, 0, "setup: {}", made.stderr);
        }
        for entry in holding {
            let planted = shell
                .run(&format!(
                    "printf '#!/bin/sh\\necho FOUND-{entry}\\n' > /home/lash/{entry}/tool && \
                     chmod +x /home/lash/{entry}/tool"
                ))
                .await;
            assert_eq!(planted.status, 0, "setup: {}", planted.stderr);
        }
    });
    shell
}

/// The `exec` admissions among `seen`.
fn exec_decisions(seen: &[String]) -> Vec<&String> {
    seen.iter().filter(|e| e.starts_with("exec ")).collect()
}

/// Every `PATH` entry the walk visits, rendered as its interceptor saw it.
fn on_path<'a>(seen: &'a [String], entries: &[&str]) -> Vec<&'a String> {
    seen.iter()
        .filter(|e| {
            entries
                .iter()
                .any(|entry| e.contains(&format!("/home/lash/{entry}/")))
        })
        .collect()
}

/// A command found in the third `PATH` entry costs one `exec` decision, and the first two entries
/// raise a `locate` and nothing else.
#[test]
fn path_resolution_raises_one_exec_decision_for_the_selected_candidate() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = shell_on_three_entries(interceptor, &["three"]);
    admitted.lock().unwrap().clear();

    let out = run(shell.run("tool"));
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert!(out.stdout.contains("FOUND-three"), "{}", rendered(&out));

    let seen = admitted.lock().unwrap().clone();
    let exec_on_path: Vec<_> = exec_decisions(&seen)
        .into_iter()
        .filter(|e| e.contains("/home/lash/"))
        .collect();
    assert_eq!(
        exec_on_path,
        vec!["exec /home/lash/three/tool"],
        "one exec decision, naming the selected candidate: {seen:?}"
    );
    assert_eq!(
        on_path(&seen, &["one", "two"]),
        vec!["locate /home/lash/one/tool", "locate /home/lash/two/tool"],
        "an entry that holds nothing is a locate and no decision: {seen:?}"
    );
}

/// `command -v` and `hash` resolve through the same walk, so each costs the same one decision.
#[test]
fn command_v_and_hash_resolve_with_the_same_single_decision() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = shell_on_three_entries(interceptor, &["three"]);

    for (payload, expected_stdout) in [
        ("command -v tool", "/home/lash/three/tool\n"),
        ("hash tool", ""),
    ] {
        admitted.lock().unwrap().clear();
        let out = run(shell.run(payload));
        assert_eq!(out.status, 0, "{payload}: {}", out.stderr);
        assert_eq!(out.stdout, expected_stdout, "{payload}");

        let seen = admitted.lock().unwrap().clone();
        assert_eq!(
            exec_decisions(&seen),
            vec!["exec /home/lash/three/tool"],
            "{payload}: one exec decision, for the selected candidate: {seen:?}"
        );
        assert_eq!(
            on_path(&seen, &["one", "two"]),
            vec!["locate /home/lash/one/tool", "locate /home/lash/two/tool"],
            "{payload}: the entries that hold nothing are locates and no decision: {seen:?}"
        );
    }
}

/// A denied candidate is presented once and refused, and the walk goes on to the next entry.
#[test]
fn a_denied_candidate_is_refused_and_the_walk_continues() {
    let denials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&denials);
    let (interceptor, admitted) = Recorder::denying(move |e| {
        let denied = e == "exec /home/lash/one/tool";
        if denied {
            counted.fetch_add(1, Ordering::SeqCst);
        }
        denied
    });
    let mut shell = shell_on_three_entries(interceptor, &["one", "two"]);
    admitted.lock().unwrap().clear();

    let out = run(shell.run("tool"));
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert!(out.stdout.contains("FOUND-two"), "{}", rendered(&out));
    assert_eq!(
        denials.load(Ordering::SeqCst),
        1,
        "the denied candidate is presented once and refused"
    );

    let seen = admitted.lock().unwrap().clone();
    let exec_on_path: Vec<_> = exec_decisions(&seen)
        .into_iter()
        .filter(|e| e.contains("/home/lash/"))
        .collect();
    assert_eq!(
        exec_on_path,
        vec!["exec /home/lash/two/tool"],
        "the permitted candidate is the one admitted decision: {seen:?}"
    );
}

/// A candidate whose `locate` is refused raises no `exec`, and the walk goes on to the next entry.
#[test]
fn a_refused_locate_raises_no_exec_and_the_walk_continues() {
    let (interceptor, admitted) = Recorder::denying(|e| e == "locate /home/lash/one/tool");
    let mut shell = shell_on_three_entries(interceptor, &["one", "two"]);
    admitted.lock().unwrap().clear();

    let out = run(shell.run("tool"));
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert!(out.stdout.contains("FOUND-two"), "{}", rendered(&out));

    let seen = admitted.lock().unwrap().clone();
    assert_eq!(
        on_path(&seen, &["one"]),
        Vec::<&String>::new(),
        "a refused locate is followed by nothing for that entry: {seen:?}"
    );
    let exec_on_path: Vec<_> = exec_decisions(&seen)
        .into_iter()
        .filter(|e| e.contains("/home/lash/"))
        .collect();
    assert_eq!(exec_on_path, vec!["exec /home/lash/two/tool"], "{seen:?}");
}

/// A `PATH` entry the kernel does not mount is `not found` with no `exec` decision, and the same
/// directory, once bound, is found with one.
#[cfg(unix)]
#[test]
fn a_path_entry_outside_the_kernels_reach_is_not_observed() {
    let directory =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("unreached-path-entry");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("host directory");
    let tool = directory.join("tool");
    std::fs::write(&tool, "#!/bin/sh\necho FOUND-host\n").expect("host tool");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let host = directory
        .to_str()
        .expect("UTF-8 host directory")
        .to_string();

    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut unbound = support::builder()
        .effect_interceptor(interceptor)
        .env("PATH", host.as_str())
        .build()
        .expect("shell builds");
    let out = run(unbound.run("command -v tool"));
    assert_eq!(out.status, 1, "{}", rendered(&out));
    assert!(out.stdout.is_empty(), "{}", rendered(&out));
    let seen = admitted.lock().unwrap().clone();
    assert!(
        exec_decisions(&seen).is_empty(),
        "an entry outside the kernel's reach raises no exec decision: {seen:?}"
    );

    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut bound = support::builder()
        .effect_interceptor(interceptor)
        .bind_direct(host.as_str(), "/tools")
        .env("PATH", format!("{host}:/tools"))
        .build()
        .expect("shell builds");
    let out = run(bound.run("command -v tool"));
    assert_eq!(out.status, 0, "{}", rendered(&out));
    assert_eq!(out.stdout, "/tools/tool\n");
    let seen = admitted.lock().unwrap().clone();
    assert_eq!(
        exec_decisions(&seen),
        vec!["exec /tools/tool"],
        "the bound entry is found with one decision, the unbound one raises none: {seen:?}"
    );
}

/// Numbers each `ghost` decision and records what happened to each.
struct Ghosts {
    decided: AtomicUsize,
    events: Arc<Mutex<Vec<String>>>,
}

struct GhostPermit {
    number: usize,
    events: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl EffectPermit for GhostPermit {
    async fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        if let EffectOutcome::ShellCommand { reported_status } = outcome {
            let line = format!("#{} status {reported_status}", self.number);
            self.events.lock().unwrap().push(line);
        }
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {
        let line = format!("#{} indeterminate", self.number);
        self.events.lock().unwrap().push(line);
    }
}

#[async_trait]
impl EffectInterceptor for Ghosts {
    async fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let EffectAttempt::ShellRun { program, .. } = effect else {
            return Ok(Box::new(GhostPermit {
                number: 0,
                events: Arc::new(Mutex::new(Vec::new())),
            }));
        };
        if *program == "blocked" {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "blocked"));
        }
        let number = self.decided.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(Box::new(GhostPermit {
            number,
            events: Arc::clone(&self.events),
        }))
    }
}

/// Run each script on one Shell, settling the Call after each as the box does, and return the
/// events each decision recorded, sorted.
fn ghosts(scripts: &[&str]) -> (Vec<strands_shell::Output>, Vec<String>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let kernel = Arc::new(support::kernel(Arc::new(Ghosts {
        decided: AtomicUsize::new(0),
        events: Arc::clone(&events),
    })));
    let mut shell = Shell::with_kernel(Arc::clone(&kernel) as Arc<dyn strands_shell::os::Kernel>);
    let outputs = run(async {
        let mut outputs = Vec::new();
        for script in scripts {
            outputs.push(shell.run(script).await);
            kernel.settle();
        }
        outputs
    });
    let mut events = events.lock().unwrap().clone();
    events.sort();
    (outputs, events)
}

/// A fallback stage decided but never run is settled when its Call ends, so a later Call
/// records its own outcome on its own decision.
#[test]
fn a_fallback_stage_that_never_runs_does_not_carry_its_decision_into_a_later_call() {
    let (outputs, events) = ghosts(&["ghost | blocked", "ghost"]);
    assert_eq!(outputs[0].status, 126, "{}", outputs[0].stderr);
    assert_eq!(outputs[1].status, 127, "{}", outputs[1].stderr);
    assert_eq!(events, ["#1 indeterminate", "#2 status 127"]);
}

/// A fallback stage whose redirect fails is settled when its Call ends.
#[test]
fn a_fallback_stage_whose_redirect_fails_is_settled_when_its_call_ends() {
    let (outputs, events) = ghosts(&["ghost > /denied/out", "ghost"]);
    assert_eq!(outputs[1].status, 127, "{}", outputs[1].stderr);
    assert_eq!(events, ["#1 indeterminate", "#2 status 127"]);
}

/// Each fallback stage of a pipeline that runs is decided once and records its own outcome,
/// even when two stages are the same command or an inner pipeline is refused.
#[test]
fn each_fallback_stage_that_runs_is_decided_once() {
    let (_outputs, events) = ghosts(&["ghost | ghost"]);
    assert_eq!(events, ["#1 status 127", "#2 status 127"]);
    let (_outputs, events) = ghosts(&["{ blocked; true; } | ghost"]);
    assert_eq!(events, ["#1 status 127", "#2 status 0"]);
}

// ── `mkdir -p` decides each component once ───────────────────────────────────────────────────

/// How many metadata decisions `script` makes for each path, in the order first seen.
fn metadata_decisions(
    shell: &mut Shell,
    recorder: &Recorder,
    script: &str,
) -> Vec<(String, usize)> {
    recorder.attempted.lock().unwrap().clear();
    let out = run(shell.run(script));
    assert_eq!(out.status, 0, "{script}: {}", rendered(&out));
    let mut counts: Vec<(String, usize)> = Vec::new();
    for attempt in recorder.attempted.lock().unwrap().iter() {
        let Some(path) = attempt.strip_prefix("meta(follow=true) ") else {
            continue;
        };
        match counts.iter_mut().find(|(seen, _)| seen == path) {
            Some((_, count)) => *count += 1,
            None => counts.push((path.to_string(), 1)),
        }
    }
    counts
}

/// `mkdir -p` makes one metadata decision for each component, whether the ancestor is missing,
/// exists, or is refused, in the memory filesystem and in a host folder.
#[test]
fn mkdir_p_makes_one_metadata_decision_per_component() {
    let directory = tempfile::tempdir().expect("host folder");
    for root in ["/home/lash", "/workspace"] {
        let refused = format!("meta(follow=true) {root}");
        let (recorder, _, armed) = Recorder::armable(move |effect| {
            effect == "meta(follow=true) /home" || effect == refused
        });
        let mut shell = support::builder()
            .bind_direct(directory.path().to_str().expect("UTF-8"), "/workspace")
            .effect_interceptor(Arc::clone(&recorder) as Arc<dyn EffectInterceptor>)
            .build()
            .expect("shell builds");
        let once = |paths: &[&str]| -> Vec<(String, usize)> {
            paths
                .iter()
                .map(|path| (format!("{root}/{path}"), 1))
                .collect()
        };
        let created = format!("cd {root} && mkdir -p m/a/b/c");
        let missing = once(&["m", "m/a", "m/a/b", "m/a/b/c"]);
        assert_eq!(
            metadata_decisions(&mut shell, &recorder, &created),
            missing,
            "missing"
        );
        assert_eq!(
            metadata_decisions(&mut shell, &recorder, &created),
            missing,
            "existing"
        );

        armed.store(true, Ordering::SeqCst);
        let mut expected: Vec<(String, usize)> = if root == "/home/lash" {
            vec![("/home".into(), 1), ("/home/lash".into(), 1)]
        } else {
            vec![("/workspace".into(), 1)]
        };
        expected.extend(once(&["r", "r/a", "r/a/b"]));
        assert_eq!(
            metadata_decisions(&mut shell, &recorder, &format!("mkdir -p {root}/r/a/b")),
            expected,
            "refused"
        );
    }
}
