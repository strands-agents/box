//! A bare name that the embedder declares runs its declared file, before any host `PATH` lookup.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use strands_shell::os::{HostPrograms, HostSpawn, HostSpawnOutcome, HostSpawner};
use strands_shell::{EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, Shell};

/// A permit that records nothing and refuses nothing.
struct Pass;

#[async_trait]
impl EffectPermit for Pass {
    async fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> std::io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

/// One command decision: the action, the program as spelled, and the path a spawn names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decided {
    Run(String),
    Spawn { program: String, path: String },
}

/// Admits every attempt and records each command decision.
struct Recorder(Arc<Mutex<Vec<Decided>>>);

#[async_trait]
impl EffectInterceptor for Recorder {
    async fn intercept(
        &self,
        effect: &EffectAttempt<'_>,
    ) -> std::io::Result<Box<dyn EffectPermit>> {
        let decided = match effect {
            EffectAttempt::ShellRun { program, .. } => Some(Decided::Run((*program).to_string())),
            EffectAttempt::ShellSpawn {
                program,
                program_path,
                ..
            } => Some(Decided::Spawn {
                program: (*program).to_string(),
                path: (*program_path).to_string(),
            }),
            _ => None,
        };
        if let Some(decided) = decided {
            self.0.lock().expect("record").push(decided);
        }
        Ok(Box::new(Pass))
    }
}

/// Records the program and `argv[0]` spelling each host spawn receives.
fn recording_spawner(received: Arc<Mutex<Vec<(PathBuf, PathBuf)>>>) -> HostSpawner {
    Arc::new(move |spawn: HostSpawn| {
        let received = Arc::clone(&received);
        Box::pin(async move {
            received
                .lock()
                .expect("record")
                .push((spawn.program.clone(), spawn.invoked.clone()));
            Ok(HostSpawnOutcome {
                status: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        })
    })
}

/// What one script did: its status and stderr, each decision, and each spawn.
struct Ran {
    status: i32,
    stderr: String,
    decided: Vec<Decided>,
    received: Vec<(PathBuf, PathBuf)>,
}

fn run(script: &str, declared: &[(&str, &Path)]) -> Ran {
    let programs: HostPrograms = Arc::new(
        declared
            .iter()
            .map(|(name, path)| ((*name).to_string(), path.to_path_buf()))
            .collect::<BTreeMap<_, _>>(),
    );
    let decided = Arc::new(Mutex::new(Vec::new()));
    let received = Arc::new(Mutex::new(Vec::new()));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let local = tokio::task::LocalSet::new();
    let out = local.block_on(&rt, async {
        let mut shell = Shell::builder()
            .disable_network()
            .effect_interceptor(Arc::new(Recorder(Arc::clone(&decided))))
            .host_spawner(recording_spawner(Arc::clone(&received)))
            .host_programs(programs)
            .build()
            .expect("shell builds");
        shell.run(script).await
    });
    rt.block_on(local);
    Ran {
        status: out.status,
        stderr: out.stderr,
        decided: decided.lock().expect("read").clone(),
        received: received.lock().expect("read").clone(),
    }
}

/// A canonical fixture folder with an executable `real/tool` and a link `bin/tool` to it.
fn fixture(name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("real")).expect("a fixture folder");
    std::fs::create_dir_all(base.join("bin")).expect("a fixture folder");
    let base = base.canonicalize().expect("a canonical fixture");
    std::fs::write(base.join("real/tool"), "#!/bin/sh\n").expect("a program");
    std::fs::set_permissions(
        base.join("real/tool"),
        std::fs::Permissions::from_mode(0o755),
    )
    .expect("an executable program");
    std::os::unix::fs::symlink(base.join("real/tool"), base.join("bin/tool")).expect("a link");
    base
}

/// The canonical file that the host `PATH` finds for `name`.
fn on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .and_then(|found| found.canonicalize().ok())
}

/// **A declared bare name runs its declared file, not the first match on `PATH`.** The decision
/// names the file's canonical identity and keeps the name as typed, and the seam receives the
/// declared spelling as `argv[0]`.
#[cfg(unix)]
#[test]
fn a_declared_bare_name_runs_its_declared_file_before_path() {
    let base = fixture("declared-before-path");
    let declared = base.join("bin/tool");
    let ran = run("hostname -s", &[("hostname", &declared)]);

    assert_eq!(ran.status, 0, "stderr: {}", ran.stderr);
    assert_eq!(
        ran.decided,
        vec![Decided::Spawn {
            program: "hostname".into(),
            path: base.join("real/tool").display().to_string(),
        }]
    );
    assert_eq!(ran.received, vec![(base.join("real/tool"), declared)]);
}

/// **A bare name with no declaration still resolves on the host `PATH`.**
#[cfg(unix)]
#[test]
fn an_undeclared_bare_name_still_resolves_on_path() {
    let Some(found) = on_path("hostname") else {
        eprintln!("skipping: no `hostname` on PATH");
        return;
    };
    let base = fixture("undeclared-on-path");
    let ran = run("hostname", &[("other", &base.join("bin/tool"))]);

    assert_eq!(ran.status, 0, "stderr: {}", ran.stderr);
    assert_eq!(
        ran.decided,
        vec![Decided::Spawn {
            program: "hostname".into(),
            path: found.display().to_string(),
        }]
    );
}

/// **A spelling with a separator names its own path**, even one that a declaration spells.
#[cfg(unix)]
#[test]
fn a_spelling_with_a_separator_ignores_the_declarations() {
    let base = fixture("separator-ignores-declarations");
    let other = base.join("real/other");
    std::fs::copy(base.join("real/tool"), &other).expect("a second program");
    let spelled = other.display().to_string();
    let ran = run(&spelled, &[(spelled.as_str(), &base.join("bin/tool"))]);

    assert_eq!(ran.status, 0, "stderr: {}", ran.stderr);
    assert_eq!(
        ran.decided,
        vec![Decided::Spawn {
            program: other.display().to_string(),
            path: other.display().to_string(),
        }]
    );
}

/// **A builtin, a Shell command, and a function keep precedence over a declared name.**
#[cfg(unix)]
#[test]
fn the_shells_own_programs_keep_precedence_over_a_declared_name() {
    let base = fixture("shell-programs-first");
    let declared = base.join("bin/tool");
    let ran = run(
        "cd . ; echo hi ; basename /a/b ; greet() { :; } ; greet",
        &[
            ("cd", &declared),
            ("echo", &declared),
            ("basename", &declared),
            ("greet", &declared),
        ],
    );

    assert_eq!(ran.status, 0, "stderr: {}", ran.stderr);
    assert!(
        ran.received.is_empty(),
        "nothing spawned: {:?}",
        ran.received
    );
    assert!(
        ran.decided
            .iter()
            .all(|decided| matches!(decided, Decided::Run(_))),
        "{:?}",
        ran.decided
    );
}

/// **A declared file that is gone is not found, and `PATH` is not searched instead.** The decision
/// names the declared path, and nothing reaches the seam.
#[cfg(unix)]
#[test]
fn a_missing_declared_file_is_not_found_on_path_instead() {
    let base = fixture("declared-file-gone");
    let gone = base.join("bin/gone");
    let ran = run("hostname", &[("hostname", &gone)]);

    assert_eq!(ran.status, 127, "stderr: {}", ran.stderr);
    assert!(ran.stderr.contains("command not found"), "{}", ran.stderr);
    assert_eq!(
        ran.decided,
        vec![Decided::Spawn {
            program: "hostname".into(),
            path: gone.display().to_string(),
        }]
    );
    assert!(ran.received.is_empty(), "{:?}", ran.received);
}
