//! The kernel effect seam: every effect is admitted individually, not the command.
//!
//! One `shell:run` admission expands into many kernel effects. These tests pin the
//! expansion, the fail-closed behavior of each denial path, and the outcome each
//! operation reports.

use std::io;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use strands_shell::os::Kernel;
use strands_shell::vfs_kernel::VfsKernel;
use strands_shell::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, EffectResult, FsOperation,
    FsPairOperation, Shell,
};
use strands_shell::{Follow, Resolved};

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
    ///
    /// For tests whose *setup* must legitimately touch the very path the payload is
    /// then forbidden to touch — creating a protected file before proving it cannot
    /// be overwritten. Arming after setup keeps the precondition honest instead of
    /// carving a hole in the predicate that the payload could also slip through.
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
    Shell::builder()
        .effect_interceptor(interceptor)
        .build()
        .expect("shell builds")
}

/// The headline property: one admission per **resolved command**, many individually-admitted
/// effects underneath each.
///
/// The payload writes through a glob-driven loop, copies, then deletes — so it
/// exercises enumeration, repeated append opens, a two-path read/write copy, and a
/// no-follow probe before a delete.
///
/// The command count is no longer 1. Admission moved from the submitted text to the resolved
/// command, so a submission running `mkdir`, `cat`, `cp`, and `rm` is four decisions rather
/// than one — each naming the program it authorizes. That is the point of the move: a single
/// verdict over a whole line could not say which program it was granting.
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

/// A denied write is refused even though the command itself was admitted.
#[test]
fn denying_a_write_effect_blocks_it_under_an_admitted_command() {
    let (interceptor, _) = Recorder::denying(|e| e.starts_with("write(") && e.contains("blocked"));
    let mut shell = shell_with(interceptor);

    let (allowed, denied) = run(async {
        let allowed = shell.run("printf 'ok' > /home/lash/fine.txt").await;
        let denied = shell.run("printf 'no' > /home/lash/blocked.txt").await;
        (allowed, denied)
    });

    assert_eq!(allowed.status, 0, "unrelated write: {}", allowed.stderr);
    assert_ne!(denied.status, 0, "denied write must fail");

    let content = run(async { shell.read_file("/home/lash/blocked.txt").await });
    assert!(
        content.is_err(),
        "a denied write must not leave content behind"
    );
}

/// Enumeration is its own decision: denying the glob starves the loop that follows.
#[test]
fn denying_enumeration_yields_no_matches() {
    let (interceptor, _) = Recorder::denying(|e| e.starts_with("enumerate"));
    let mut shell = shell_with(interceptor);

    let out = run(async {
        let setup = shell
            .run("mkdir -p /home/lash/g && printf 'x' > /home/lash/g/one.txt")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        shell
            .run("for f in /home/lash/g/*.txt; do printf 'saw:%s\\n' \"$f\"; done")
            .await
    });

    // A denied glob expands to nothing, so the pattern stays literal and no real
    // file is ever read.
    assert!(
        !out.stdout.contains("one.txt"),
        "a denied enumeration must not reveal matches: {:?}",
        out.stdout
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

/// A symlink cannot launder a denied read.
///
/// `abs` normalizes a path string but does not follow symlinks. Admitting its output
/// would authorize the link's own name while the kernel reads the link's target, so a
/// rule denying a path could be evaded by reading a symlink pointing at it. Following
/// operations are therefore admitted on the canonical target.
#[test]
fn a_symlink_cannot_launder_a_denied_read() {
    let (interceptor, admitted) = Recorder::denying(|e| e == "read /home/lash/secret");
    let mut shell = shell_with(interceptor);

    let out = run(async {
        let setup = shell
            .run("printf 'TOPSECRET' > /home/lash/secret && ln -s /home/lash/secret /home/lash/alias")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        shell.run("cat /home/lash/alias").await
    });

    assert!(
        !out.stdout.contains("TOPSECRET"),
        "reading through a symlink must hit the same denial: {:?}",
        out.stdout
    );
    let seen = admitted.lock().unwrap().clone();
    assert!(
        !seen.iter().any(|e| e == "read /home/lash/alias"),
        "the link's own name must never be what gets authorized: {seen:?}"
    );
}

/// A *directory* symlink cannot launder mutations into a protected subtree.
///
/// The sharper form of the previous test, and the one that defeats prefix rules — the
/// dominant Cedar shape — without needing a link per file. It also covers the
/// not-yet-existing leaf: canonicalizing the whole path fails for a create, so the
/// existing ancestors must be resolved and the missing tail re-appended.
#[test]
fn a_directory_symlink_cannot_launder_mutations() {
    let (interceptor, admitted) = Recorder::denying(|e| {
        let mutating =
            e.starts_with("write(") || e.starts_with("remove_file") || e.starts_with("create_dir");
        mutating && e.contains("/home/lash/secrets/")
    });
    let mut shell = shell_with(interceptor);

    let (new_file, existing, made_dir, content) = run(async {
        let setup = shell
            .run("mkdir -p /home/lash/secrets && ln -s /home/lash/secrets /home/lash/alias")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        admitted.lock().unwrap().clear();

        let new_file = shell.run("printf 'PWNED' > /home/lash/alias/newfile").await;
        let existing = shell.run("printf 'PWNED' > /home/lash/alias/key.pem").await;
        let made_dir = shell.run("mkdir /home/lash/alias/sub").await;
        let content = shell.run("cat /home/lash/secrets/newfile").await;
        (new_file, existing, made_dir, content)
    });

    assert_ne!(
        new_file.status, 0,
        "creating through a dir symlink must deny"
    );
    assert_ne!(
        existing.status, 0,
        "overwriting through a dir symlink must deny"
    );
    assert_ne!(made_dir.status, 0, "mkdir through a dir symlink must deny");
    assert!(
        !content.stdout.contains("PWNED"),
        "nothing may land in the protected subtree: {:?}",
        content.stdout
    );

    // The command text legitimately names the alias — it is the unparsed submission.
    // No *effect* admission may, because that is what authorization binds to.
    let effects: Vec<_> = admitted
        .lock()
        .unwrap()
        .iter()
        .filter(|e| !e.starts_with("shell:run"))
        .cloned()
        .collect();
    assert!(
        !effects.iter().any(|e| e.contains("/home/lash/alias/")),
        "the alias spelling must never be what gets authorized: {effects:?}"
    );
}

/// A read-write open (`<>`) needs the read authorization too.
///
/// The implementation hands back a reader seeded with current content, so admitting it
/// as write-only would disclose a file under a write-only permit.
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
///
/// The mirror of the test above: `lstat`, `read_link`, and `rm` act on the name
/// itself, so resolving the final symlink there would authorize the wrong object.
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
///
/// The Shell raises no network attempt at all. That is stronger than the
/// query-stripping it replaces: there is no request attempt for a secret to leak
/// into.
///
/// The `shell:run` admission is a deliberate exception and is excluded here. It
/// carries the command exactly as submitted — including any secret the caller put in
/// it — because a command-authorizing rule must see the real text. Redacting it would
/// mean authorizing something the workload did not run. Any interceptor that journals
/// command submissions is therefore handling secret-bearing material by design.
#[test]
fn no_effect_attempt_carries_a_request_url() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = Shell::builder()
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

/// `mv` through a directory symlink must be judged on the resolved destination.
///
/// The acceptance proof for the resolved-capability seam. `Kernel::open` routes its path
/// through `resolved_target`, which follows symlinks; `Kernel::rename` routes through
/// `Self::abs`, which does not. So the
/// same laundering attack that `a_directory_symlink_cannot_launder_mutations`
/// already blocks for `>` and `mkdir` succeeds via `mv`: policy is asked about
/// `/home/lash/alias/key.pem` while the bytes land in `/home/lash/secrets/key.pem`.
///
/// Closed by the resolved-capability seam: `Kernel::rename` takes `Resolved`, so it
/// cannot receive an unresolved spelling, and `Mediated::rename` resolves both sides
/// before admission.
#[test]
fn mv_through_a_directory_symlink_is_judged_on_its_target() {
    // Deny every mutation naming the protected subtree, armed only after setup —
    // setup must create the protected file, which the payload is then forbidden to
    // replace. The command text is exempt because it legitimately names the alias:
    // it is the unparsed submission, not an effect identity.
    let (interceptor, admitted, armed) =
        Recorder::armable(|e| !e.starts_with("shell:run") && e.contains("/home/lash/secrets/"));
    let mut shell = shell_with(interceptor);

    let (moved, content) = run(async {
        let setup = shell
            .run(
                "mkdir -p /home/lash/secrets \
                 && printf 'original' > /home/lash/secrets/key.pem \
                 && ln -s /home/lash/secrets /home/lash/alias \
                 && printf 'PWNED' > /home/lash/payload",
            )
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        armed.store(true, Ordering::SeqCst);
        admitted.lock().unwrap().clear();

        let moved = shell
            .run("mv /home/lash/payload /home/lash/alias/key.pem")
            .await;
        // Disarm to verify: the check reads the protected file by its real name, so
        // the assertion cannot be satisfied by the alias pointing somewhere harmless.
        armed.store(false, Ordering::SeqCst);
        let content = shell.run("cat /home/lash/secrets/key.pem").await;
        (moved, content)
    });

    assert_ne!(
        moved.status, 0,
        "mv through a directory symlink must be denied, not merely audited"
    );
    assert_eq!(
        content.stdout, "original",
        "the protected file must be untouched"
    );

    let effects: Vec<_> = admitted
        .lock()
        .unwrap()
        .iter()
        .filter(|e| !e.starts_with("shell:run"))
        .cloned()
        .collect();
    assert!(
        !effects.iter().any(|e| e.contains("/home/lash/alias/")),
        "the alias spelling must never be the authorized identity: {effects:?}"
    );
}

/// `mkdir -p` creates no ancestor whose metadata probe is denied.
///
/// A denied probe reports not-found, which is also what a missing directory reports. The
/// builtin must not act on that answer for an ancestor: it creates only below the first
/// component the kernel reports missing, and raises no `create_dir` above it.
#[test]
fn mkdir_p_creates_no_ancestor_whose_probe_is_denied() {
    let above_the_grant = ["/home", "/home/lash", "/home/lash/project"];
    let (interceptor, admitted, armed) = Recorder::armable(move |effect| {
        above_the_grant
            .iter()
            .any(|path| effect.ends_with(&format!(" {path}")))
    });
    let mut shell = shell_with(interceptor.clone());

    let (made, listing, setup_attempts) = run(async {
        let setup = shell.run("mkdir -p /home/lash/project").await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        let setup_attempts = interceptor.attempted.lock().unwrap().len();
        armed.store(true, Ordering::SeqCst);
        let made = shell.run("mkdir -p /home/lash/project/c/d").await;
        let listing = shell.run("ls /home/lash/project/c").await;
        (made, listing, setup_attempts)
    });

    assert_eq!(made.status, 0, "{}", made.stderr);
    assert_eq!(listing.stdout.trim(), "d", "{}", listing.stderr);
    let admitted = admitted.lock().unwrap();
    assert!(
        admitted.contains(&"create_dir /home/lash/project/c".to_string())
            && admitted.contains(&"create_dir /home/lash/project/c/d".to_string()),
        "{admitted:?}"
    );
    let attempted = interceptor.attempted.lock().unwrap();
    let created_above = attempted[setup_attempts..]
        .iter()
        .filter(|effect| effect.starts_with("create_dir "))
        .filter(|effect| {
            above_the_grant
                .iter()
                .any(|path| effect.ends_with(&format!(" {path}")))
        })
        .collect::<Vec<_>>();
    assert!(
        created_above.is_empty(),
        "no create_dir may reach an ancestor the probe could not see: {created_above:?}"
    );
}

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

/// `Kernel::resolve` is the sole mint point for a path identity.
///
/// Tested directly rather than through a command, because these are the properties
/// every admission then depends on: get resolution wrong and every downstream
/// decision is made about the wrong object.
mod resolve {
    use super::run;
    use strands_shell::Shell;
    use strands_shell::os::{Follow, Kernel};

    /// Build a shell, run `setup`, and hand back its kernel plus a process for
    /// probing.
    ///
    /// The process is freshly minted rather than cloned from the shell: `resolve`
    /// reads only the working directory, and `Process` is deliberately not `Clone`.
    fn kernel_after(setup: &str) -> (std::sync::Arc<dyn Kernel>, strands_shell::os::Process) {
        // The kernel is constructed here rather than borrowed from a built Shell,
        // because `Shell` now hands out the *mediated* handle and these tests probe
        // `Kernel::resolve` itself — resolution below the admission layer.
        //
        // Seeded via `build_vfs`, not a bare `Vfs::new()`: the standard tree creates
        // `/home/lash`, and without it every setup command fails with
        // "mkdir: permission denied".
        let vfs =
            strands_shell::vfs_config::build_vfs(&Default::default()).expect("standard vfs builds");
        let trait_object: std::sync::Arc<dyn Kernel> =
            std::sync::Arc::new(strands_shell::vfs_kernel::VfsKernel::new(vfs));
        let mut shell = Shell::builder()
            .kernel(trait_object.clone())
            .build()
            .expect("shell builds");
        let out = run(async { shell.run(setup).await });
        assert_eq!(out.status, 0, "setup: {}", out.stderr);
        let proc = trait_object.new_process();
        (trait_object, proc)
    }

    /// The working directory is applied and `..` folded, with no symlink involved.
    #[test]
    fn applies_cwd_and_folds_dot_dot() {
        let (kernel, proc) = kernel_after("mkdir -p /home/lash/a/b && printf x > /home/lash/n");
        let resolved = run(async { kernel.resolve(&proc, "a/b/../../n", Follow::Yes).await });
        assert_eq!(resolved.path(), "/home/lash/n");
        assert_eq!(resolved.follow(), Follow::Yes);
    }

    /// `Follow::Yes` resolves a final symlink; `Follow::No` leaves it alone.
    ///
    /// The pair that makes the disposition load-bearing: the same input string yields
    /// two different identities, and each is correct for its own operation.
    #[test]
    fn follow_decides_whether_a_final_symlink_resolves() {
        let (kernel, proc) = kernel_after(
            "mkdir -p /home/lash/real && printf x > /home/lash/real/f \
             && ln -s /home/lash/real/f /home/lash/link",
        );

        let followed = run(async { kernel.resolve(&proc, "/home/lash/link", Follow::Yes).await });
        assert_eq!(followed.path(), "/home/lash/real/f");

        let kept = run(async { kernel.resolve(&proc, "/home/lash/link", Follow::No).await });
        assert_eq!(kept.path(), "/home/lash/link");
    }

    /// A leaf that does not exist yet resolves under its real parent.
    ///
    /// This is the create case a directory symlink exploits: authorizing the
    /// unresolved spelling would judge `/alias/new` instead of `/secrets/new`.
    #[test]
    fn a_missing_leaf_resolves_under_a_symlinked_ancestor() {
        let (kernel, proc) = kernel_after(
            "mkdir -p /home/lash/secrets && ln -s /home/lash/secrets /home/lash/alias",
        );
        let resolved = run(async {
            kernel
                .resolve(&proc, "/home/lash/alias/newfile", Follow::Yes)
                .await
        });
        assert_eq!(resolved.path(), "/home/lash/secrets/newfile");
    }

    /// Several missing levels — `mkdir -p` deep — keep the whole tail.
    #[test]
    fn several_missing_levels_are_appended_to_the_canonical_base() {
        let (kernel, proc) = kernel_after(
            "mkdir -p /home/lash/secrets && ln -s /home/lash/secrets /home/lash/alias",
        );
        let resolved = run(async {
            kernel
                .resolve(&proc, "/home/lash/alias/x/y/z", Follow::Yes)
                .await
        });
        assert_eq!(resolved.path(), "/home/lash/secrets/x/y/z");
    }

    /// With nothing on the path resolvable, the normalized spelling is the identity.
    ///
    /// It names no existing object, so a rule matching it denies a create — the
    /// fail-closed direction.
    #[test]
    fn an_unresolvable_path_falls_back_to_its_normalized_spelling() {
        let (kernel, proc) = kernel_after("printf x > /home/lash/anchor");
        let resolved = run(async {
            kernel
                .resolve(&proc, "/nonexistent/deep/leaf", Follow::Yes)
                .await
        });
        assert_eq!(resolved.path(), "/nonexistent/deep/leaf");
    }

    /// A dangling symlink resolves to the path it names, as the kernel follows it.
    #[test]
    fn a_dangling_symlink_resolves_to_the_path_it_names() {
        let (kernel, proc) = kernel_after(
            "mkdir -p /tmp/probes && ln -s /nonexistent_probe /tmp/probes/missing \
             && ln -s ../gone /tmp/probes/relative \
             && ln -s /tmp/probes/missing /tmp/probes/chained",
        );
        let resolve = |path: &'static str, follow| {
            run(async { kernel.resolve(&proc, path, follow).await.path().to_string() })
        };
        assert_eq!(
            resolve("/tmp/probes/missing/x", Follow::Yes),
            "/nonexistent_probe/x"
        );
        assert_eq!(
            resolve("/tmp/probes/missing", Follow::Yes),
            "/nonexistent_probe"
        );
        assert_eq!(
            resolve("/tmp/probes/relative/x", Follow::Yes),
            "/tmp/gone/x"
        );
        assert_eq!(
            resolve("/tmp/probes/chained/x/y", Follow::Yes),
            "/nonexistent_probe/x/y"
        );
        assert_eq!(
            resolve("/tmp/probes/missing/x", Follow::No),
            "/nonexistent_probe/x"
        );
        assert_eq!(
            resolve("/tmp/probes/missing", Follow::No),
            "/tmp/probes/missing"
        );
    }

    /// A symlink loop ends resolution instead of hanging it.
    #[test]
    fn a_symlink_loop_terminates() {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (kernel, proc) = kernel_after("ln -s /tmp/b /tmp/a && ln -s /tmp/a /tmp/b");
            let resolved = run(async { kernel.resolve(&proc, "/tmp/a/x", Follow::Yes).await });
            let _ = sender.send(resolved.path().to_string());
        });
        let resolved = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("resolution of a symlink loop must end");
        assert!(resolved.ends_with("/x"), "{resolved}");
    }
}

/// A denial does not depend on whether a symlink's target exists.
///
/// `cd` through a link to an existing path and through a link to a missing
/// path must both be judged on the target, so the error does not tell them apart.
#[test]
fn a_dangling_symlink_is_no_existence_oracle() {
    let (interceptor, admitted) = Recorder::denying(|e| {
        e.starts_with("change_dir ")
            && !e.starts_with("change_dir /tmp")
            && !e.starts_with("change_dir /home/lash")
    });
    let mut shell = shell_with(interceptor);

    let (present, missing) = run(async {
        let setup = shell
            .run(
                "mkdir -p /tmp/probes && ln -s /usr /tmp/probes/present \
                 && ln -s /nonexistent_probe /tmp/probes/missing",
            )
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        (
            shell.run("cd /tmp/probes/present/x").await,
            shell.run("cd /tmp/probes/missing/x").await,
        )
    });

    assert!(
        present
            .stderr
            .contains("test policy denied: change_dir /usr/x"),
        "{}",
        present.stderr
    );
    assert!(
        missing
            .stderr
            .contains("test policy denied: change_dir /nonexistent_probe/x"),
        "{}",
        missing.stderr
    );
    let seen = admitted.lock().unwrap().clone();
    assert!(
        !seen
            .iter()
            .any(|e| e.starts_with("change_dir /tmp/probes/")),
        "a symlink's own name must never be what gets authorized: {seen:?}"
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
///
/// Neither the verdict nor the error may depend on the link's target.
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

/// A kernel built without an interceptor is unchanged.
#[test]
fn an_unmediated_shell_still_works() {
    let mut shell = Shell::builder().build().expect("shell builds");
    let out = run(async {
        shell
            .run("mkdir -p /home/lash/plain && printf 'hi' > /home/lash/plain/f && cat /home/lash/plain/f")
            .await
    });
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(out.stdout, "hi");
}

/// A caller-supplied kernel is mediated exactly as the bundled one is.
///
/// This is the property the resolved-capability seam exists for. Admission used to
/// live inside `VfsKernel`, so `.effect_interceptor(p).kernel(k)` compiled, emitted no
/// warning, and enforced policy on the *command* while every file effect underneath it
/// went unchecked. The seam moved admission above the trait, so the backend an embedder
/// chooses can no longer decide whether policy applies.
///
/// The delegating kernel below is the shape a real third-party kernel takes — it
/// forwards to a `VfsKernel` and adds no admission of its own, exactly as an S3- or
/// database-backed implementation would.
#[test]
fn a_supplied_kernel_is_mediated_identically() {
    struct Delegating {
        inner: VfsKernel,
    }

    #[async_trait]
    impl Kernel for Delegating {
        fn new_process(&self) -> strands_shell::os::Process {
            self.inner.new_process()
        }
        async fn resolve(
            &self,
            proc: &strands_shell::os::Process,
            path: &str,
            follow: Follow,
        ) -> Resolved {
            self.inner.resolve(proc, path, follow).await
        }
        fn isatty(&self, fd: i32) -> bool {
            self.inner.isatty(fd)
        }
        fn now(&self) -> std::time::SystemTime {
            self.inner.now()
        }
        async fn settle_writes(&self) -> Vec<strands_shell::os::WriteFailure> {
            self.inner.settle_writes().await
        }
        async fn open(
            &self,
            proc: &mut strands_shell::os::Process,
            path: Resolved,
            flags: strands_shell::os::OpenFlags,
        ) -> io::Result<strands_shell::os::Fd> {
            self.inner.open(proc, path, flags).await
        }
        async fn list_dir(
            &self,
            proc: &strands_shell::os::Process,
            path: Resolved,
        ) -> io::Result<Vec<strands_shell::os::DirEntry>> {
            self.inner.list_dir(proc, path).await
        }
        async fn change_dir(
            &self,
            proc: &mut strands_shell::os::Process,
            path: Resolved,
        ) -> io::Result<()> {
            self.inner.change_dir(proc, path).await
        }
        async fn stat(
            &self,
            proc: &strands_shell::os::Process,
            path: Resolved,
        ) -> strands_shell::os::FileStat {
            self.inner.stat(proc, path).await
        }
        async fn lstat(
            &self,
            proc: &strands_shell::os::Process,
            path: Resolved,
        ) -> strands_shell::os::FileStat {
            self.inner.lstat(proc, path).await
        }
        async fn access(
            &self,
            proc: &strands_shell::os::Process,
            path: Resolved,
            mode: i32,
        ) -> bool {
            self.inner.access(proc, path, mode).await
        }
        async fn canonicalize(
            &self,
            proc: &strands_shell::os::Process,
            path: Resolved,
        ) -> io::Result<std::path::PathBuf> {
            self.inner.canonicalize(proc, path).await
        }
        async fn is_executable(&self, proc: &strands_shell::os::Process, path: Resolved) -> bool {
            self.inner.is_executable(proc, path).await
        }
        async fn glob(&self, proc: &strands_shell::os::Process, pattern: &str) -> Vec<String> {
            self.inner.glob(proc, pattern).await
        }
        async fn remove_file(
            &self,
            proc: &strands_shell::os::Process,
            path: Resolved,
        ) -> io::Result<()> {
            self.inner.remove_file(proc, path).await
        }
        async fn remove_dir(
            &self,
            proc: &strands_shell::os::Process,
            path: Resolved,
        ) -> io::Result<()> {
            self.inner.remove_dir(proc, path).await
        }
        async fn create_dir(
            &self,
            proc: &strands_shell::os::Process,
            path: Resolved,
        ) -> io::Result<()> {
            self.inner.create_dir(proc, path).await
        }
        async fn rename(
            &self,
            proc: &strands_shell::os::Process,
            from: Resolved,
            to: Resolved,
        ) -> io::Result<()> {
            self.inner.rename(proc, from, to).await
        }
        async fn symlink(
            &self,
            proc: &strands_shell::os::Process,
            target: &str,
            link: Resolved,
        ) -> io::Result<()> {
            self.inner.symlink(proc, target, link).await
        }
        async fn read_link(
            &self,
            proc: &strands_shell::os::Process,
            path: Resolved,
        ) -> io::Result<String> {
            self.inner.read_link(proc, path).await
        }
        async fn set_permissions(
            &self,
            proc: &strands_shell::os::Process,
            path: Resolved,
            mode: u32,
        ) -> io::Result<()> {
            self.inner.set_permissions(proc, path, mode).await
        }
        fn check_url(&self, url: &str) -> io::Result<()> {
            self.inner.check_url(url)
        }
    }

    let (interceptor, admitted, armed) =
        Recorder::armable(|e| !e.starts_with("shell:run") && e.contains("/home/lash/guarded/"));
    let vfs = strands_shell::vfs_config::build_vfs(&Default::default()).expect("vfs builds");
    let supplied: Arc<dyn Kernel> = Arc::new(Delegating {
        inner: VfsKernel::new(vfs),
    });
    let mut shell = Shell::builder()
        .effect_interceptor(interceptor)
        .kernel(supplied)
        .build()
        .expect("shell builds");

    let (blocked, elsewhere, content) = run(async {
        let setup = shell
            .run("mkdir -p /home/lash/guarded && printf 'original' > /home/lash/guarded/f")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        armed.store(true, Ordering::SeqCst);

        let blocked = shell.run("printf 'PWNED' > /home/lash/guarded/f").await;
        let elsewhere = shell.run("printf 'fine' > /home/lash/open.txt").await;
        armed.store(false, Ordering::SeqCst);
        let content = shell.run("cat /home/lash/guarded/f").await;
        (blocked, elsewhere, content)
    });

    assert_ne!(
        blocked.status, 0,
        "a supplied kernel must not escape admission"
    );
    assert_eq!(
        content.stdout, "original",
        "the guarded file must be untouched"
    );
    assert_eq!(
        elsewhere.status, 0,
        "an unrelated write still succeeds: {}",
        elsewhere.stderr
    );

    let effects: Vec<_> = admitted
        .lock()
        .unwrap()
        .iter()
        .filter(|e| !e.starts_with("shell:run"))
        .cloned()
        .collect();
    assert!(
        !effects.is_empty(),
        "effects under a supplied kernel must reach the interceptor"
    );
}

/// Every mutating operation is judged on the resolved target, not the alias.
///
/// Task 13's coverage sweep. The originally-reported hole was `mv`, but the defect was
/// per-method resolution, so the *class* is what needs pinning: one denial rule, one
/// symlinked directory, and every operation that reaches through it. `>` / `mkdir` were
/// already covered elsewhere; `mv`, `rm`, `rmdir`, `chmod`, and a read via `cat` were
/// not.
#[test]
fn no_mutating_operation_can_launder_through_a_directory_symlink() {
    let (interceptor, _admitted, armed) =
        Recorder::armable(|e| !e.starts_with("shell:run") && e.contains("/home/lash/vault/"));
    let mut shell = shell_with(interceptor);

    let outcomes = run(async {
        let setup = shell
            .run(
                "mkdir -p /home/lash/vault/sub \
                 && printf 'original' > /home/lash/vault/f \
                 && printf 'payload' > /home/lash/src \
                 && ln -s /home/lash/vault /home/lash/alias",
            )
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        armed.store(true, Ordering::SeqCst);

        // Each reaches the protected subtree only through the alias.
        let cases = vec![
            (
                "mv",
                shell.run("mv /home/lash/src /home/lash/alias/f").await,
            ),
            ("rm", shell.run("rm /home/lash/alias/f").await),
            ("rmdir", shell.run("rmdir /home/lash/alias/sub").await),
            ("chmod", shell.run("chmod 777 /home/lash/alias/f").await),
            ("cat", shell.run("cat /home/lash/alias/f").await),
        ];

        armed.store(false, Ordering::SeqCst);
        let survived = shell.run("cat /home/lash/vault/f").await;
        (cases, survived)
    });

    let (cases, survived) = outcomes;
    for (label, out) in &cases {
        assert_ne!(
            out.status, 0,
            "{label} through a directory symlink must be denied: {}",
            out.stderr
        );
    }
    assert_eq!(
        survived.stdout, "original",
        "the guarded file must be untouched by any of them"
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
    let mut shell = Shell::builder()
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
    let mut shell = Shell::builder()
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
    use strands_shell::vfs_config::{BindEntry, BindMode, VfsConfig, build_vfs};
    use tokio::io::AsyncWriteExt as _;

    let directory =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("deferred-host-write-inode");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("host bind");
    let source = directory.join("source");
    let decoy = directory.join("decoy");
    let admitted = directory.join("admitted");
    std::fs::write(&source, "original").expect("protected source");
    std::fs::write(&decoy, "decoy").expect("decoy");
    let config = VfsConfig {
        bind: vec![BindEntry {
            mode: BindMode::Direct,
            source: directory.to_str().expect("UTF-8").to_string(),
            destination: "/workspace".to_string(),
            readonly: false,
        }],
        ..Default::default()
    };
    let kernel = VfsKernel::new(build_vfs(&config).expect("vfs builds"));
    let mut proc = Kernel::new_process(&kernel);
    proc.cwd = std::path::PathBuf::from("/workspace");

    run(async {
        let resolved = kernel.resolve(&proc, "decoy", Follow::Yes).await;
        let fd = kernel
            .open(&mut proc, resolved, strands_shell::os::OpenFlags::write())
            .await
            .expect("the decoy opens");

        std::fs::rename(&decoy, &admitted).expect("move the admitted inode");
        std::fs::hard_link(&source, &decoy).expect("replace the pathname with the protected inode");
        let mut writer = proc.take_writer(fd).expect("writer");
        writer.write_all(b"PWNED").await.expect("write");
        drop(writer);

        for _ in 0..100 {
            if matches!(
                std::fs::read_to_string(&admitted),
                Ok(contents) if contents == "PWNED"
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
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

/// Every route that evaluates command text is admitted, not just `Shell::run`.
///
/// **Four routes bypassed admission entirely until 2026-08-08**, and this is the guard.
/// Admission lived in `Shell::run`/`Shell::execute`, while Lua's `io.popen` and
/// `os.execute`, `find -exec`, and `xargs` re-entered `exec::execute` from *inside* the
/// crate. All four are reachable from an already-admitted command, so none needed a new
/// grant: one permitted command fanned out to N unjudged ones, and a policy counting
/// `shell:run` saw a single decision.
///
/// Asserted as *presence in the admitted list*, keyed on a marker unique to the nested
/// command, so the test cannot pass merely because the outer command was admitted.
#[test]
fn every_nested_command_route_is_admitted() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);

    run(async {
        let setup = shell.run("printf SEED > /tmp/seed.txt").await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);

        // Each entry is (payload, the marker that must appear in an admitted command).
        // The marker is the *nested* text, never the outer command's.
        for (payload, nested) in [
            (
                r"find /tmp -name seed.txt -exec printf NESTED_VIA_FIND {} ;",
                "printf NESTED_VIA_FIND",
            ),
            (
                "printf /tmp/seed.txt | xargs printf NESTED_VIA_XARGS",
                "printf NESTED_VIA_XARGS",
            ),
            (
                r#"lua -e "local h=io.popen([[printf NESTED_VIA_POPEN]]); io.write(h:read([[a]]) or [[none]])""#,
                "printf NESTED_VIA_POPEN",
            ),
            (
                r#"lua -e "os.execute([[printf NESTED_VIA_OS_EXECUTE]])""#,
                "printf NESTED_VIA_OS_EXECUTE",
            ),
            // `sh <file>` reaches `execute_sourced` through `run_script`, and `.` through the
            // source builtin — **both bypass `execute` entirely**, which is why admission had to
            // move down to the two callees. Measured 2026-08-09: with the gate on `execute`,
            // these two ran text a `forbid` rule named while `find -exec` was denied.
            (
                "printf 'printf NESTED_VIA_SH\n' > /tmp/n1.sh; sh /tmp/n1.sh",
                "printf NESTED_VIA_SH",
            ),
            (
                "printf 'printf NESTED_VIA_SOURCE\n' > /tmp/n2.sh; . /tmp/n2.sh",
                "printf NESTED_VIA_SOURCE",
            ),
            // Command substitution is deliberately NOT here: its inner text is always a
            // literal substring of the submission, so a `contains` assertion would pass on
            // the outer command's own admission entry and prove nothing. It needs exact-entry
            // matching — see `command_substitution_is_admitted_as_its_own_event`.
        ] {
            admitted.lock().unwrap().clear();
            let out = shell.run(payload).await;
            assert_eq!(out.status, 0, "{payload} failed: {}", out.stderr);

            let seen = admitted.lock().unwrap().clone();
            assert!(
                seen.iter().any(|entry| entry.contains(nested)),
                "the nested command {nested:?} must be admitted in its own right, not folded \
                 into {payload:?}; admitted: {seen:?}"
            );
        }
    });
}

/// A nested command the policy refuses does not run, from any of the four routes.
///
/// The counterpart to the test above: admission that is *recorded* but not *enforced* would
/// satisfy the presence assertion while still executing the command. Here the interceptor
/// denies exactly the nested text and the payload's output must not contain it.
#[test]
fn a_denied_nested_command_does_not_run() {
    let (interceptor, _admitted) = Recorder::denying(|effect| effect.contains("printf LAUNDERED"));
    let mut shell = shell_with(interceptor);

    run(async {
        let setup = shell.run("printf SEED > /tmp/seed2.txt").await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);

        for payload in [
            r"find /tmp -name seed2.txt -exec printf LAUNDERED_FIND {} ;",
            "printf /tmp/seed2.txt | xargs printf LAUNDERED_XARGS",
            r#"lua -e "local h=io.popen([[printf LAUNDERED_POPEN]]); io.write(h:read([[a]]) or [[none]])""#,
            r#"lua -e "os.execute([[printf LAUNDERED_OS_EXECUTE]])""#,
            // The two routes that bypassed `execute`. The forbidden text is built so the OUTER
            // command never contains the marker — otherwise the outer admission would deny and
            // the test would pass without proving the nested route is judged.
            "W=LAUND; X=ERED_SH; printf \"printf ${W}${X}\\n\" > /tmp/d1.sh; sh /tmp/d1.sh",
            "W=LAUND; X=ERED_SRC; printf \"printf ${W}${X}\\n\" > /tmp/d2.sh; . /tmp/d2.sh",
            // A trap body assembled from a file: text the submission never contained.
            "V=$(cat /tmp/d1.sh); trap \"$V\" EXIT; printf outer",
        ] {
            let out = shell.run(payload).await;
            assert!(
                !out.stdout.contains("LAUNDERED"),
                "a refused nested command must not execute: {payload:?} produced {:?}",
                out.stdout
            );
        }
    });
}

/// A substitution's inner text is admitted as its own event, matched **exactly**.
///
/// The exactness is the whole test. A substitution's inner text is always a literal substring
/// of the submission, so a `contains` assertion — the shape
/// [`every_nested_command_route_is_admitted`] uses for the other six routes — passes on the
/// *outer* command's admission entry whether or not the substitution was ever judged.
/// Measured: with the gate removed entirely, a `contains` version of this test still passed.
/// Only an exact whole-entry match discriminates.
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
///
/// This is the property the move to post-resolution admission bought, and it is a strictly
/// stronger claim than the one this test made before. The forbidden marker is assembled from
/// two variables, so it appears nowhere in the submitted text; the old seam admitted the
/// substitution's *unexpanded* source (`printf "${W}${X}"`) and therefore could not see it at
/// all. Its own documentation recorded that as a residual: "it is not a claim that policy sees
/// post-expansion text."
///
/// It is now. Admission happens after expansion, so the attempt names `printf` with the
/// laundered argument, and a rule written against the value that runs refuses it.
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
///
/// **This is the property the substitution gap actually cost**, and it is worth stating
/// precisely because the more obvious framing is wrong. `capture_output`'s `cmd` is the
/// substitution's *unexpanded* source text, so it is always a literal substring of the
/// submission the outer gate already judged — admitting it does **not** close a
/// text-laundering hole, and a test asserting that it does would be asserting something
/// false. (Pre-expansion admission is a separate documented residual, and plain variable
/// expansion exhibits it with no substitution involved at all.)
///
/// What was missing is the **event**. Before the fix, ten substitutions inside one
/// submission produced *one* decision while the same ten through `eval`, `xargs`, or
/// `source` produced eleven — so a policy counting them, or an audit reading temporal
/// history, saw substitution fan-out as nothing at all. The equality against the other
/// routes is the assertion, because parity is the point.
///
/// The absolute count is now **ten, not eleven**. The eleventh was the submission itself, and
/// there is no longer a decision over a submission — only over each resolved command. Parity
/// across the three routes is unchanged, which is what this test is for.
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
    let mut shell = Shell::builder()
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

/// A denied selection does not run, and the workload sees the absent answer it saw before.
#[test]
fn a_denied_selected_candidate_does_not_run() {
    let (interceptor, _) = Recorder::denying(|e| e == "exec /home/lash/three/tool");
    let mut shell = shell_on_three_entries(interceptor, &["three"]);

    let (invoked, located) =
        run(async { (shell.run("tool").await, shell.run("command -v tool").await) });
    assert_ne!(invoked.status, 0, "{}", rendered(&invoked));
    assert!(
        !invoked.stdout.contains("FOUND-three"),
        "the denied program must not run: {}",
        rendered(&invoked)
    );
    assert!(
        invoked.stderr.contains("tool: command not found"),
        "a denied candidate is absent, as it was before: {}",
        rendered(&invoked)
    );
    assert_eq!(located.status, 1, "{}", rendered(&located));
    assert!(located.stdout.is_empty(), "{}", rendered(&located));
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
    let mut unbound = Shell::builder()
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
    let mut bound = Shell::builder()
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
