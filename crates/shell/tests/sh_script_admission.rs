//! `sh FILE` and `lash FILE` are decided as the program that runs them: the Shell's own interpreter.

mod support;

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use box_shell::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, HostPrograms, HostSpawner,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Decision {
    Exec(String),
    Spawn(String),
}

/// Records each command decision, and refuses a `shell:exec` of `refused`.
struct Recorder {
    decisions: Arc<Mutex<Vec<Decision>>>,
    refused: Option<&'static str>,
}

#[async_trait]
impl EffectInterceptor for Recorder {
    async fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        match effect {
            EffectAttempt::ShellRun { program, .. } => {
                self.decisions
                    .lock()
                    .unwrap()
                    .push(Decision::Exec((*program).to_string()));
                if self.refused == Some(*program) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "test policy denied command",
                    ));
                }
            }
            EffectAttempt::ShellSpawn { program_path, .. } => {
                self.decisions
                    .lock()
                    .unwrap()
                    .push(Decision::Spawn((*program_path).to_string()));
            }
            _ => {}
        }
        Ok(Box::new(Pass))
    }
}

struct Pass;

#[async_trait]
impl EffectPermit for Pass {
    async fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

fn recording_spawner(received: Arc<Mutex<Vec<PathBuf>>>) -> HostSpawner {
    Arc::new(move |spawn: box_shell::HostSpawn| {
        let received = Arc::clone(&received);
        Box::pin(async move {
            received.lock().unwrap().push(spawn.program.clone());
            Ok(box_shell::HostSpawnOutcome {
                status: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        })
    })
}

/// `sh` and `lash` declared as a host file, so a decision that reached the host lookup would spawn.
fn declared_interpreters() -> HostPrograms {
    Arc::new(BTreeMap::from([
        ("sh".to_string(), PathBuf::from("/bin/sh")),
        ("lash".to_string(), PathBuf::from("/bin/sh")),
    ]))
}

struct Run {
    status: i32,
    stdout: String,
    decisions: Vec<Decision>,
    spawned: Vec<PathBuf>,
}

/// Write `script` to `/tmp/judged.sh`, then run `command` with only its own decisions recorded,
/// with `sh` and `lash` declared as the host `/bin/sh`.
fn run_script(command: &str, script: &str, refused: Option<&'static str>) -> Run {
    let decisions = Arc::new(Mutex::new(Vec::new()));
    let spawned = Arc::new(Mutex::new(Vec::new()));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    let (status, stdout) = runtime.block_on(local.run_until(async {
        let mut shell = support::builder()
            .effect_interceptor(Arc::new(Recorder {
                decisions: Arc::clone(&decisions),
                refused,
            }))
            .host_spawner(recording_spawner(Arc::clone(&spawned)))
            .programs(declared_interpreters())
            .build()
            .unwrap();
        let setup = shell
            .run(&format!(
                "printf '%s' '{script}' > /tmp/judged.sh && chmod +x /tmp/judged.sh"
            ))
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        decisions.lock().unwrap().clear();
        let out = shell.run(command).await;
        (out.status, out.stdout)
    }));
    let decisions = decisions.lock().unwrap().clone();
    let spawned = spawned.lock().unwrap().clone();
    Run {
        status,
        stdout,
        decisions,
        spawned,
    }
}

#[test]
fn sh_file_is_decided_as_the_shells_own_interpreter() {
    let run = run_script("sh /tmp/judged.sh", "echo SCRIPT_RAN\n", None);
    assert_eq!(run.status, 0);
    assert_eq!(run.stdout, "SCRIPT_RAN\n");
    assert_eq!(
        run.decisions,
        [Decision::Exec("sh".into()), Decision::Exec("echo".into())]
    );
    assert!(run.spawned.is_empty(), "spawned: {:?}", run.spawned);
}

#[test]
fn lash_file_is_decided_like_sh_file() {
    let run = run_script("lash /tmp/judged.sh", "echo SCRIPT_RAN\n", None);
    assert_eq!(run.status, 0);
    assert_eq!(run.stdout, "SCRIPT_RAN\n");
    assert_eq!(
        run.decisions,
        [Decision::Exec("lash".into()), Decision::Exec("echo".into())]
    );
    assert!(run.spawned.is_empty(), "spawned: {:?}", run.spawned);
}

#[test]
fn a_refused_sh_does_not_run_the_file() {
    let run = run_script("sh /tmp/judged.sh", "echo SCRIPT_RAN\n", Some("sh"));
    assert_eq!(run.status, 126);
    assert_eq!(run.stdout, "");
    assert_eq!(run.decisions, [Decision::Exec("sh".into())]);
    assert!(run.spawned.is_empty(), "spawned: {:?}", run.spawned);
}

#[test]
fn a_bin_sh_file_is_decided_as_sh() {
    let run = run_script("/bin/sh /tmp/judged.sh", "echo SCRIPT_RAN\n", None);
    assert_eq!(run.status, 0);
    assert_eq!(run.stdout, "SCRIPT_RAN\n");
    assert_eq!(
        run.decisions,
        [Decision::Exec("sh".into()), Decision::Exec("echo".into())]
    );
    assert!(run.spawned.is_empty(), "spawned: {:?}", run.spawned);
}

#[test]
fn a_bin_sh_interpreter_line_in_memory_is_decided_as_sh() {
    let run = run_script("/tmp/judged.sh", "#!/bin/sh\necho SCRIPT_RAN\n", None);
    assert_eq!(run.status, 0);
    assert_eq!(run.stdout, "SCRIPT_RAN\n");
    assert_eq!(
        run.decisions,
        [Decision::Exec("sh".into()), Decision::Exec("echo".into())]
    );
    assert!(run.spawned.is_empty(), "spawned: {:?}", run.spawned);
}

#[test]
fn a_bin_lash_file_is_decided_as_lash() {
    let run = run_script("/bin/lash /tmp/judged.sh", "echo SCRIPT_RAN\n", None);
    assert_eq!(run.status, 0);
    assert_eq!(run.stdout, "SCRIPT_RAN\n");
    assert_eq!(
        run.decisions,
        [Decision::Exec("lash".into()), Decision::Exec("echo".into())]
    );
    assert!(run.spawned.is_empty(), "spawned: {:?}", run.spawned);
}

#[test]
fn a_rule_on_sh_alone_does_not_refuse_lash() {
    let run = run_script("lash /tmp/judged.sh", "echo SCRIPT_RAN\n", Some("sh"));
    assert_eq!(run.status, 0);
    assert_eq!(run.stdout, "SCRIPT_RAN\n");
    assert_eq!(
        run.decisions,
        [Decision::Exec("lash".into()), Decision::Exec("echo".into())]
    );
}
