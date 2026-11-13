//! A command the Shell does not implement reports its own outcome: a lost write and a cancel are
//! both recorded.

use std::io;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use box_shell::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, Filesystem, HostSpawnOutcome,
    HostSpawner, ScriptOutcome, ScriptRunner, ShellKernel,
};
use strands_shell::Shell;

/// Permits every effect and records what happened to each `python3` and host-program decision.
struct Outcomes(Arc<Mutex<Vec<String>>>);

struct PythonPermit(Arc<Mutex<Vec<String>>>);

#[async_trait]
impl EffectPermit for PythonPermit {
    async fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        if let EffectOutcome::ShellCommand { reported_status } = outcome {
            self.0
                .lock()
                .unwrap()
                .push(format!("status {reported_status}"));
        }
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {
        self.0.lock().unwrap().push("indeterminate".to_string());
    }
}

struct Unrecorded;

#[async_trait]
impl EffectPermit for Unrecorded {
    async fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

#[async_trait]
impl EffectInterceptor for Outcomes {
    async fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        match effect {
            EffectAttempt::ShellRun { program, .. } if *program == "python3" => {
                Ok(Box::new(PythonPermit(Arc::clone(&self.0))))
            }
            EffectAttempt::ShellSpawn { .. } => Ok(Box::new(PythonPermit(Arc::clone(&self.0)))),
            _ => Ok(Box::new(Unrecorded)),
        }
    }
}

/// A Shell whose memory files hold `max_file_size` bytes and whose Python runs `runner`.
fn shell(max_file_size: usize, runner: ScriptRunner) -> (Shell, Arc<Mutex<Vec<String>>>) {
    shell_spawning(max_file_size, runner, None)
}

/// As [`shell`], with host programs run by `spawner`.
fn shell_spawning(
    max_file_size: usize,
    runner: ScriptRunner,
    spawner: Option<HostSpawner>,
) -> (Shell, Arc<Mutex<Vec<String>>>) {
    let mut vfs = strands_shell::vfs_config::build_vfs(&Default::default()).expect("vfs");
    vfs.max_file_size = max_file_size;
    let filesystem = Arc::new(Filesystem::serving(vfs, &[]).expect("a filesystem"));
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let mut kernel = ShellKernel::over(filesystem, Arc::new(Outcomes(Arc::clone(&outcomes))))
        .python(1024, runner);
    if let Some(spawner) = spawner {
        kernel = kernel.spawner(spawner);
    }
    (kernel.shell(), outcomes)
}

fn run<F: std::future::Future>(body: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tokio::task::LocalSet::new().block_on(&runtime, body)
}

/// A Python command whose output does not fit its file fails, and records that failure.
#[test]
fn python_output_cut_off_at_the_file_limit_fails_and_records_the_failure() {
    let printing: ScriptRunner = Arc::new(|_| {
        Box::pin(async {
            ScriptOutcome {
                status: 0,
                stdout: "PAYLOAD\n".to_string(),
                stderr: String::new(),
            }
        })
    });
    let (mut shell, outcomes) = shell(4, printing);
    let (out, kept) = run(async {
        let out = shell.run("python3 -c 'print(1)' > /tmp/out").await;
        let kept = shell.run("cat /tmp/out").await;
        (out, kept)
    });
    assert_eq!(out.status, 1, "{}", out.stderr);
    assert!(out.stderr.contains("file size limit"), "{}", out.stderr);
    assert_eq!(kept.stdout, "PAYL");
    assert_eq!(*outcomes.lock().unwrap(), ["status 1"]);
}

/// A Python command cancelled while it runs records an indeterminate outcome.
#[test]
fn a_cancelled_python_command_records_an_indeterminate_outcome() {
    let hanging: ScriptRunner = Arc::new(|_| Box::pin(std::future::pending()));
    let (mut shell, outcomes) = shell(1024, hanging);
    run(async {
        let call = shell.run("python3 -c 'fetch()'");
        let cancelled = tokio::time::timeout(std::time::Duration::from_millis(200), call).await;
        assert!(cancelled.is_err(), "the script never finishes");
    });
    assert_eq!(*outcomes.lock().unwrap(), ["indeterminate"]);
}

/// A runner that prints `PAYLOAD` and succeeds.
fn printing() -> ScriptRunner {
    Arc::new(|_| {
        Box::pin(async {
            ScriptOutcome {
                status: 0,
                stdout: "PAYLOAD\n".to_string(),
                stderr: String::new(),
            }
        })
    })
}

/// A host program file, and a spawner that answers every spawn with `outcome`, or never answers.
fn host_program(outcome: Option<(i32, &'static str)>) -> (tempfile::TempDir, String, HostSpawner) {
    use std::os::unix::fs::PermissionsExt as _;
    let folder = tempfile::tempdir().expect("a folder");
    let path = folder.path().join("prog");
    std::fs::write(&path, "#!/bin/sh\n").expect("a program");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let spawner: HostSpawner = Arc::new(move |_| match outcome {
        Some((status, stdout)) => Box::pin(async move {
            Ok(HostSpawnOutcome {
                status,
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
            })
        }),
        None => Box::pin(std::future::pending()),
    });
    let path = path.to_str().expect("UTF-8").to_string();
    (folder, path, spawner)
}

/// A host program cancelled while it runs records an indeterminate outcome.
#[cfg(unix)]
#[test]
fn a_cancelled_host_program_records_an_indeterminate_outcome() {
    let (_folder, program, spawner) = host_program(None);
    let (mut shell, outcomes) = shell_spawning(1024, printing(), Some(spawner));
    run(async {
        let call = shell.run(&program);
        let cancelled = tokio::time::timeout(std::time::Duration::from_millis(200), call).await;
        assert!(cancelled.is_err(), "the program never finishes");
    });
    assert_eq!(*outcomes.lock().unwrap(), ["indeterminate"]);
}

/// A host program whose output does not fit its file fails, and records that failure.
#[cfg(unix)]
#[test]
fn host_output_cut_off_at_the_file_limit_fails_and_records_the_failure() {
    let (_folder, program, spawner) = host_program(Some((0, "PAYLOAD\n")));
    let (mut shell, outcomes) = shell_spawning(4, printing(), Some(spawner));
    let out = run(shell.run(&format!("{program} > /tmp/out")));
    assert_eq!(out.status, 1, "{}", out.stderr);
    assert!(out.stderr.contains("file size limit"), "{}", out.stderr);
    assert_eq!(*outcomes.lock().unwrap(), ["status 1"]);
}

/// Output to a reader that closed is no failure, as `SIGPIPE` ends a writer quietly.
#[cfg(unix)]
#[test]
fn output_to_a_closed_reader_keeps_the_status_and_reports_nothing() {
    let late = std::time::Duration::from_millis(100);
    let printing_late: ScriptRunner = Arc::new(move |_| {
        Box::pin(async move {
            tokio::time::sleep(late).await;
            ScriptOutcome {
                status: 0,
                stdout: "PAYLOAD\n".to_string(),
                stderr: String::new(),
            }
        })
    });
    let (_folder, program, _) = host_program(None);
    let spawner: HostSpawner = Arc::new(move |_| {
        Box::pin(async move {
            tokio::time::sleep(late).await;
            Ok(HostSpawnOutcome {
                status: 0,
                stdout: b"PAYLOAD\n".to_vec(),
                stderr: Vec::new(),
            })
        })
    });
    let (mut shell, outcomes) = shell_spawning(1024, printing_late, Some(spawner));
    let outs = run(async {
        let python = shell.run("python3 -c x | true").await;
        let host = shell.run(&format!("{program} | true")).await;
        (python, host)
    });
    for out in [outs.0, outs.1] {
        assert_eq!(out.status, 0, "{}", out.stderr);
        assert_eq!(out.stderr, "");
    }
    assert_eq!(*outcomes.lock().unwrap(), ["status 0", "status 0"]);
}

/// `command -v`, `command -V`, and `type` find both Python names.
#[test]
fn python_is_found_by_command_lookup() {
    let (mut shell, _) = shell(1024, printing());
    for query in [
        "command -v python3",
        "command -V python3",
        "type python3",
        "command -v python",
    ] {
        let out = run(shell.run(query));
        assert_eq!(out.status, 0, "{query}: {}", out.stderr);
    }
}

/// An executable script named `python3` on `PATH` does not shadow Monty.
#[test]
fn a_path_script_does_not_shadow_python() {
    let (mut shell, _) = shell(1024, printing());
    let out = run(shell.run(
        "printf '#!/bin/sh\\nprintf SHADOW\\n' > /tmp/python3 && chmod +x /tmp/python3 && \
         PATH=/tmp\npython3 -c x",
    ));
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(out.stdout, "PAYLOAD\n");
}
