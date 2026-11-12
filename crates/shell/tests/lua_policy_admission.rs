//! Each Lua filesystem and command effect is admitted on its own and fails closed when denied.

mod support;

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use box_shell::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, FsOperation, FsPairOperation,
};
use strands_shell::Shell;

/// One admitted effect, rendered as the stable string the deny predicate matches on.
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
        _ => "unknown".to_string(),
    }
}

/// Records every admission and denies whatever a test's predicate names.
struct Recorder {
    admitted: Arc<Mutex<Vec<String>>>,
    denied: Arc<Mutex<Vec<String>>>,
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
            admitted: Arc::clone(&admitted),
            denied: Arc::new(Mutex::new(Vec::new())),
            deny: Box::new(deny),
        });
        (interceptor, admitted)
    }

    /// The effects this recorder refused.
    fn denied(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.denied)
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
        if (self.deny)(&rendered) {
            self.denied.lock().unwrap().push(rendered.clone());
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("test policy denied: {rendered}"),
            ));
        }
        self.admitted.lock().unwrap().push(rendered);
        Ok(Box::new(NoopPermit))
    }
}

/// A permit that records nothing.
struct NoopPermit;

#[async_trait]
impl EffectPermit for NoopPermit {
    async fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
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

/// The bytes at `path`, or `None` when `cat` cannot read them.
async fn read_file(shell: &mut Shell, path: &str) -> Option<String> {
    let out = shell.run(&format!("cat {path}")).await;
    (out.status == 0).then_some(out.stdout)
}

/// A Lua `io.open` read is admitted as `read <resolved-path>`.
#[test]
fn lua_io_open_read_is_admitted() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);

    run(async {
        let setup = shell.run("printf DATA > /home/lash/r.txt").await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        admitted.lock().unwrap().clear();

        let out = shell
            .run(r#"lua -e "local f=io.open([[/home/lash/r.txt]]); io.write(f:read([[a]]))""#)
            .await;
        assert_eq!(out.status, 0, "lua io.open read: {}", out.stderr);
        assert_eq!(out.stdout, "DATA");
    });

    let seen = admitted.lock().unwrap().clone();
    assert!(
        seen.iter().any(|e| e == "read /home/lash/r.txt"),
        "io.open read must be admitted in its own right: {seen:?}"
    );
}

/// A Lua `io.open` write is admitted as `write(...) <resolved-path>`.
#[test]
fn lua_io_open_write_is_admitted() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);

    run(async {
        let out = shell
            .run(r#"lua -e "local f=io.open([[/home/lash/w.txt]],[[w]]); f:write([[X]]); f:close()""#)
            .await;
        assert_eq!(out.status, 0, "lua io.open write: {}", out.stderr);
        assert_eq!(
            read_file(&mut shell, "/home/lash/w.txt").await.as_deref(),
            Some("X")
        );
    });

    let seen = admitted.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|e| e.starts_with("write(") && e.contains("/home/lash/w.txt")),
        "io.open write must be admitted: {seen:?}"
    );
}

/// A Lua `os.remove` is admitted as `remove_file <path>`, and `os.rename` as a pair.
#[test]
fn lua_os_remove_and_rename_are_admitted() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);

    run(async {
        let setup = shell
            .run("printf A > /home/lash/gone.txt && printf B > /home/lash/from.txt")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        admitted.lock().unwrap().clear();

        let rm = shell
            .run(r#"lua -e "os.remove([[/home/lash/gone.txt]])""#)
            .await;
        assert_eq!(rm.status, 0, "os.remove: {}", rm.stderr);
        let mv = shell
            .run(r#"lua -e "os.rename([[/home/lash/from.txt]],[[/home/lash/to.txt]])""#)
            .await;
        assert_eq!(mv.status, 0, "os.rename: {}", mv.stderr);
    });

    let seen = admitted.lock().unwrap().clone();
    assert!(
        seen.iter().any(|e| e == "remove_file /home/lash/gone.txt"),
        "os.remove must be admitted: {seen:?}"
    );
    assert!(
        seen.iter()
            .any(|e| e == "rename /home/lash/from.txt -> /home/lash/to.txt"),
        "os.rename must be admitted as a pair: {seen:?}"
    );
}

/// A denied read raises in Lua and returns none of the file's bytes.
#[test]
fn lua_io_open_read_denied_leaks_no_content() {
    let (interceptor, _, armed) =
        Recorder::armable(|e| e.starts_with("read ") && e.contains("secret.txt"));
    let mut shell = shell_with(interceptor);

    let out = run(async {
        let setup = shell.run("printf TOPSECRET > /home/lash/secret.txt").await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        armed.store(true, Ordering::SeqCst);
        shell
            .run(r#"lua -e "local f=io.open([[/home/lash/secret.txt]]); io.write(f:read([[a]]))""#)
            .await
    });

    assert_ne!(out.status, 0, "a denied read must fail the script");
    assert!(
        !out.stdout.contains("TOPSECRET") && !out.stderr.contains("TOPSECRET"),
        "a denied read must reveal no bytes: stdout={:?} stderr={:?}",
        out.stdout,
        out.stderr
    );
}

/// A denied write raises on `close` and creates no file.
#[test]
fn lua_io_open_write_denied_creates_nothing() {
    let (interceptor, _) =
        Recorder::denying(|e| e.starts_with("write(") && e.contains("blocked.txt"));
    let mut shell = shell_with(interceptor);

    let (out, content) = run(async {
        let out = shell
            .run(r#"lua -e "local f=io.open([[/home/lash/blocked.txt]],[[w]]); f:write([[no]]); f:close()""#)
            .await;
        let content = read_file(&mut shell, "/home/lash/blocked.txt").await;
        (out, content)
    });

    assert_ne!(out.status, 0, "a denied write must fail the script");
    assert!(
        content.is_none(),
        "a denied write must leave no file behind"
    );
}

/// A denied `os.remove` fails, and the file survives.
#[test]
fn lua_os_remove_denied_file_survives() {
    let (interceptor, _, armed) =
        Recorder::armable(|e| e.starts_with("remove_file") && e.contains("keep.txt"));
    let mut shell = shell_with(interceptor);

    let (out, content) = run(async {
        let setup = shell.run("printf KEEP > /home/lash/keep.txt").await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        armed.store(true, Ordering::SeqCst);
        let out = shell
            .run(r#"lua -e "os.remove([[/home/lash/keep.txt]])""#)
            .await;
        let content = read_file(&mut shell, "/home/lash/keep.txt").await;
        (out, content)
    });

    assert_ne!(out.status, 0, "a denied remove must fail");
    assert_eq!(
        content.as_deref(),
        Some("KEEP"),
        "the file must survive a denied remove"
    );
}

/// `rm -f` on a policy-refused path fails and names the refused path.
#[test]
fn rm_force_on_denied_path_reports_and_fails() {
    let (interceptor, _, armed) =
        Recorder::armable(|e| e.starts_with("remove_file") && e.contains("keep.txt"));
    let mut shell = shell_with(interceptor);

    let (out, content) = run(async {
        let setup = shell.run("printf KEEP > /home/lash/keep.txt").await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        armed.store(true, Ordering::SeqCst);
        let out = shell.run("rm -f /home/lash/keep.txt").await;
        let content = read_file(&mut shell, "/home/lash/keep.txt").await;
        (out, content)
    });

    assert_ne!(out.status, 0, "rm -f on a denied path must exit non-zero");
    assert!(
        out.stderr.contains("keep.txt"),
        "rm -f must name the refused path: stderr={:?}",
        out.stderr
    );
    assert_eq!(
        content.as_deref(),
        Some("KEEP"),
        "the file must survive a denied rm -f"
    );
}

/// `rm -f` on an absent path exits 0.
#[test]
fn rm_force_on_absent_path_succeeds() {
    let (interceptor, _) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);

    let out = run(async { shell.run("rm -f /home/lash/never-existed.txt").await });

    assert_eq!(
        out.status, 0,
        "rm -f on an absent path must exit 0: {}",
        out.stderr
    );
}

/// `rm -r` names a refused child by its own path, not by its parent's path.
#[test]
fn rm_recursive_denied_child_is_named_by_its_own_path() {
    let (interceptor, _, armed) =
        Recorder::armable(|e| e.starts_with("remove_file") && e.contains("inner.txt"));
    let mut shell = shell_with(interceptor);

    let (out, inner) = run(async {
        let setup = shell
            .run("mkdir -p /home/lash/tree && printf X > /home/lash/tree/inner.txt")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        armed.store(true, Ordering::SeqCst);
        let out = shell.run("rm -r /home/lash/tree").await;
        let inner = read_file(&mut shell, "/home/lash/tree/inner.txt").await;
        (out, inner)
    });

    assert_ne!(out.status, 0, "a denied child must fail rm -r");
    assert!(
        out.stderr.contains("rm: /home/lash/tree/inner.txt:"),
        "rm -r must name the refused child, not its parent: stderr={:?}",
        out.stderr
    );
    assert_eq!(
        inner.as_deref(),
        Some("X"),
        "the refused child must survive"
    );
}

/// The directory itself reaches a delete decision when a child is refused.
#[test]
fn rm_recursive_directory_itself_reaches_a_decision() {
    let (interceptor, admitted, armed) =
        Recorder::armable(|e| e.starts_with("remove_file") && e.contains("inner.txt"));
    let mut shell = shell_with(interceptor);

    let seen = run(async {
        let setup = shell
            .run("mkdir -p /home/lash/tree && printf X > /home/lash/tree/inner.txt")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        admitted.lock().unwrap().clear();
        armed.store(true, Ordering::SeqCst);
        shell.run("rm -r /home/lash/tree").await;
        admitted.lock().unwrap().clone()
    });

    assert!(
        seen.iter().any(|e| e == "remove_dir /home/lash/tree"),
        "the directory itself must reach a delete decision even when a child is refused: {seen:?}"
    );
}

/// A denied `os.rename` fails; the source survives and the target is never created.
#[test]
fn lua_os_rename_denied_source_survives() {
    let (interceptor, _, armed) =
        Recorder::armable(|e| e.starts_with("rename") && e.contains("mv"));
    let mut shell = shell_with(interceptor);

    let (out, src, dst) = run(async {
        let setup = shell.run("printf SRC > /home/lash/mv-src.txt").await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        armed.store(true, Ordering::SeqCst);
        let out = shell
            .run(r#"lua -e "os.rename([[/home/lash/mv-src.txt]],[[/home/lash/mv-dst.txt]])""#)
            .await;
        let src = read_file(&mut shell, "/home/lash/mv-src.txt").await;
        let dst = read_file(&mut shell, "/home/lash/mv-dst.txt").await;
        (out, src, dst)
    });

    assert_ne!(out.status, 0, "a denied rename must fail");
    assert_eq!(
        src.as_deref(),
        Some("SRC"),
        "the source must survive a denied rename"
    );
    assert!(
        dst.is_none(),
        "the target must not exist after a denied rename"
    );
}

/// A module whose read the policy denies is never loaded or executed by `require`.
#[test]
fn lua_require_denied_module_does_not_execute() {
    let (interceptor, _, armed) =
        Recorder::armable(|e| e.starts_with("read ") && e.contains("evil"));
    let mut shell = shell_with(interceptor);

    let out = run(async {
        let setup = shell
            .run("printf 'print([[MODULE_RAN]])\\n' > /home/lash/evil.lua")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        armed.store(true, Ordering::SeqCst);
        shell
            .run(r#"cd /home/lash && lua -e "require([[evil]])""#)
            .await
    });

    assert_ne!(out.status, 0, "a denied module read must fail require");
    assert!(
        !out.stdout.contains("MODULE_RAN"),
        "a module whose read is denied must not execute: {:?}",
        out.stdout
    );
}

/// `loadfile` on a denied path cannot reach the bytes either.
#[test]
fn lua_loadfile_denied_path_is_refused() {
    let (interceptor, _, armed) =
        Recorder::armable(|e| e.starts_with("read ") && e.contains("locked.lua"));
    let mut shell = shell_with(interceptor);

    let out = run(async {
        let setup = shell
            .run("printf 'return 1\\n' > /home/lash/locked.lua")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        armed.store(true, Ordering::SeqCst);
        shell
            .run(r#"lua -e "local f=loadfile([[/home/lash/locked.lua]]); print(f)""#)
            .await
    });

    assert_ne!(out.status, 0, "loadfile on a denied path must fail");
}

/// A denied read cannot be laundered through `os.execute` or `io.popen`.
#[test]
fn lua_cannot_launder_a_denied_read_through_a_command() {
    for payload in [
        r#"lua -e "os.execute([[cat /home/lash/vault.txt]])""#,
        r#"lua -e "local h=io.popen([[cat /home/lash/vault.txt]]); io.write(h:read([[a]]) or [[none]])""#,
    ] {
        let (interceptor, _admitted, armed) =
            Recorder::armable(|e| e.starts_with("read ") && e.contains("vault.txt"));
        let denied = interceptor.denied();
        let mut shell = shell_with(interceptor);

        let out = run(async {
            let setup = shell.run("printf VAULTBYTES > /home/lash/vault.txt").await;
            assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
            armed.store(true, Ordering::SeqCst);
            shell.run(payload).await
        });

        assert!(
            !out.stdout.contains("VAULTBYTES"),
            "a denied read laundered through a command must reveal nothing: {payload:?} \
             produced {:?}",
            out.stdout
        );
        let denied = denied.lock().unwrap().clone();
        assert!(
            denied
                .iter()
                .any(|e| e.starts_with("read ") && e.contains("vault.txt")),
            "the nested command must have attempted the denied read: {payload:?}, \
             denied={denied:?}"
        );
    }
}

/// A relative dot-segment path from Lua is resolved before admission.
#[test]
fn lua_paths_are_resolved_before_admission() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);

    run(async {
        let setup = shell
            .run("mkdir -p /home/lash/deep && printf Z > /home/lash/deep/z.txt")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        admitted.lock().unwrap().clear();

        let out = shell
            .run(r#"cd /home/lash/deep && lua -e "local f=io.open([[../deep/z.txt]]); io.write(f:read([[a]]))""#)
            .await;
        assert_eq!(out.status, 0, "resolved read: {}", out.stderr);
        assert_eq!(out.stdout, "Z");
    });

    let seen = admitted.lock().unwrap().clone();
    assert!(
        seen.iter().any(|e| e == "read /home/lash/deep/z.txt"),
        "a relative Lua path must resolve before admission: {seen:?}"
    );
    let effects: Vec<_> = seen
        .iter()
        .filter(|e| !e.starts_with("shell:run"))
        .collect();
    assert!(
        !effects.iter().any(|e| e.contains("..")),
        "no effect admission may carry an unresolved dot segment: {effects:?}"
    );
}

/// `os.getenv` reads the Shell's own environment with no effect admission.
#[test]
fn lua_getenv_is_unmediated_and_reflects_the_environment() {
    let (interceptor, admitted) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);

    let out = run(async {
        admitted.lock().unwrap().clear();
        shell
            .run(r#"export MARKER=leaky-value && lua -e "io.write(os.getenv([[MARKER]]) or [[none]])""#)
            .await
    });

    assert_eq!(
        out.stdout, "leaky-value",
        "os.getenv reflects the env: {}",
        out.stderr
    );
    let seen = admitted.lock().unwrap().clone();
    let effects: Vec<_> = seen
        .iter()
        .filter(|e| !e.starts_with("shell:run"))
        .collect();
    assert!(
        !effects
            .iter()
            .any(|e| e.contains("MARKER") || e.contains("getenv")),
        "os.getenv is unmediated: no effect admission should mention it, saw {effects:?}"
    );
}

/// A Lua `os.getenv` cannot read the operator's process environment.
#[test]
fn lua_cannot_read_the_operators_process_environment() {
    const SEEDED: [&str; 4] = ["HOME", "PWD", "PATH", "USER"];

    let (interceptor, _admitted) = Recorder::allowing_everything();
    let mut shell = shell_with(interceptor);

    let getenv = |name: &str| format!(r#"lua -e "io.write(os.getenv([[{name}]]) or [[ABSENT]])""#);

    let (user, path, home, pwd) = run(async {
        let user = shell.run(&getenv("USER")).await.stdout;
        let path = shell.run(&getenv("PATH")).await.stdout;
        let home = shell.run(&getenv("HOME")).await.stdout;
        let pwd = shell.run(&getenv("PWD")).await.stdout;
        (user, path, home, pwd)
    });
    assert_eq!(
        user, "lash",
        "USER is the box's synthetic value, not inherited"
    );
    assert_eq!(
        path, "/usr/bin:/bin",
        "PATH is the box's synthetic value, not the operator's"
    );
    assert_eq!(home, "/home/lash", "HOME is the box's synthetic value");
    assert_eq!(pwd, "/home/lash", "PWD is the box's synthetic value");

    let operator_only = std::env::vars().map(|(k, _)| k).find(|k| {
        !SEEDED.contains(&k.as_str())
            && !k.is_empty()
            && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    });
    if let Some(name) = operator_only {
        let out = run(async { shell.run(&getenv(&name)).await });
        assert_eq!(
            out.stdout, "ABSENT",
            "a non-seeded operator variable ({name}) must not be visible to the script"
        );
    }
}
