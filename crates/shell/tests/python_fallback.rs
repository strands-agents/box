//! The kernel's Python command reports its own outcome: a lost write and a cancel are both recorded.

use std::io;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use box_shell::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, Filesystem, ScriptOutcome,
    ScriptRunner, ShellKernel,
};
use strands_shell::Shell;

/// Permits every effect and records what happened to each `python3` decision.
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
            _ => Ok(Box::new(Unrecorded)),
        }
    }
}

/// A Shell whose memory files hold `max_file_size` bytes and whose Python runs `runner`.
fn shell(max_file_size: usize, runner: ScriptRunner) -> (Shell, Arc<Mutex<Vec<String>>>) {
    let mut vfs = strands_shell::vfs_config::build_vfs(&Default::default()).expect("vfs");
    vfs.max_file_size = max_file_size;
    let filesystem = Arc::new(Filesystem::serving(vfs, &[]).expect("a filesystem"));
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let kernel = ShellKernel::over(filesystem, Arc::new(Outcomes(Arc::clone(&outcomes))))
        .python(1024, runner);
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
