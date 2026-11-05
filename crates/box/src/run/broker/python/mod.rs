//! One stateless Python interpreter per broker call, with policy-mediated host operations.

mod clock;
mod effects;
mod fetch;

use std::sync::Arc;
use std::time::Duration;

use monty::{MontyRun, RunProgress};
use monty_types::{
    CompileOptions, ExcType, ExtFunctionResult, MAX_SLEEP_SECONDS, MontyException, MontyObject,
    NameLookupResult, OsFunctionCall, OsPolicy, PrintWriter, ResourceLimits, ResourceTracker,
    SleepMode,
};
use policy::{GovernedBox, PolicyEngine, Principal, ScriptPolicyInterceptor};
use tokio::time::Instant;

use crate::run::broker::protocol::MAX_CAPTURE_STREAM_BYTES as MAX_SCRIPT_CAPTURE_BYTES;
use crate::run::broker::reach::Reach;
use crate::run::broker::shell::EgressRouting;
use crate::run::telemetry::DecisionRecorder;
use effects::{MontyPep, admit_and_perform};
use fetch::{FETCH_NAME, fetch_through_gateway};

const SCRIPT_MAX_ALLOCATION: usize = 128 * 1024 * 1024;
const SUSPENSION_LIMIT: usize = 10_000;
const BROKER_FAILURE_STATUS: i32 = 125;
const SCRIPT_RAISED_STATUS: i32 = 1;

pub(super) const PYTHON_ORIGIN: &str = "<box>";

tokio::task_local! {
    pub(super) static CALL_DEADLINE: Option<Instant>;
}

pub(super) struct PythonOutcome {
    pub(super) status: i32,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

/// Compile and run one script within its own and any enclosing Shell deadline.
pub(super) async fn run_python(
    source: String,
    reach: &Reach,
    policy: &PolicyEngine,
    governed: &GovernedBox,
    egress: Option<&EgressRouting>,
    recorder: &Arc<DecisionRecorder>,
    timeout: Option<Duration>,
) -> PythonOutcome {
    let mut captured = String::new();
    let deadline = match timeout {
        Some(timeout) => match Instant::now().checked_add(timeout) {
            Some(deadline) => Some(deadline),
            None => return raised(&deadline_exceeded(), &mut captured),
        },
        None => None,
    };
    let inherited = CALL_DEADLINE.try_with(|deadline| *deadline).ok().flatten();
    let deadline = match (deadline, inherited) {
        (Some(own), Some(enclosing)) => Some(own.min(enclosing)),
        (own, enclosing) => own.or(enclosing),
    };
    let policy_interceptor =
        ScriptPolicyInterceptor::new(policy, Principal::agent(), governed.clone());
    let policy_interceptor = match reach.reported_home() {
        Some(home) => policy_interceptor.reporting_under(home),
        None => policy_interceptor,
    };
    let interceptor = MontyPep {
        policy: policy_interceptor,
        recorder: Arc::clone(recorder),
    };
    let run = match MontyRun::new(source, PYTHON_ORIGIN, Vec::new(), CompileOptions::default()) {
        Ok(mut run) => {
            run.set_cwd(reach.working_directory());
            run.with_os_policy(OsPolicy {
                sleep: SleepMode::System(Duration::from_secs_f64(MAX_SLEEP_SECONDS)),
                ..OsPolicy::default()
            })
        }
        Err(exception) => return raised(&exception, &mut captured),
    };
    if expired(deadline) {
        return raised(&deadline_exceeded(), &mut captured);
    }
    let mut limits = ResourceLimits::default()
        .max_memory(SCRIPT_MAX_ALLOCATION)
        .max_suspensions(SUSPENSION_LIMIT);
    if let Some(deadline) = deadline {
        limits = limits.max_feed_duration(deadline.saturating_duration_since(Instant::now()));
    }
    let execution = async {
        let mut progress = match run.start(
            Vec::new(),
            ResourceTracker::new(limits),
            PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES)),
        ) {
            Ok(progress) => progress,
            Err(exception) => return raised(&exception, &mut captured),
        };
        let mut suspensions = 0_usize;
        loop {
            let exceeded = if expired(deadline) {
                Some(deadline_exceeded())
            } else if !matches!(progress, RunProgress::Complete(_)) {
                suspensions += 1;
                (suspensions > SUSPENSION_LIMIT).then(|| {
                    MontyException::new(
                        ExcType::RuntimeError,
                        Some(format!(
                            "script exceeded its limit of {SUSPENSION_LIMIT} host calls"
                        )),
                    )
                })
            } else {
                None
            };
            if let Some(exception) = exceeded {
                let writer =
                    PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES));
                let exception = abort(progress, exception, writer);
                return raised(&exception, &mut captured);
            }
            let stepped = match progress {
                RunProgress::Complete(_) => {
                    return PythonOutcome {
                        status: 0,
                        stdout: std::mem::take(&mut captured),
                        stderr: String::new(),
                    };
                }
                RunProgress::OsCall(call) if sleep_delay(&call.function_call).is_some() => {
                    let delay = sleep_delay(&call.function_call).expect("the guard proved a sleep");
                    call.tracker().on_execution_start();
                    match Instant::now().checked_add(delay) {
                        Some(wake) => tokio::time::sleep_until(wake).await,
                        None => std::future::pending().await,
                    }
                    call.tracker().on_execution_stop();
                    let writer =
                        PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES));
                    if expired(deadline) {
                        call.abort(deadline_exceeded(), writer)
                    } else if call.allow_eager_await {
                        call.resume_eager(Ok(MontyObject::none()), writer)
                    } else {
                        call.resume(MontyObject::none(), writer)
                    }
                }
                RunProgress::OsCall(mut call) => {
                    let function = std::mem::replace(
                        &mut call.function_call,
                        OsFunctionCall::Sleep(Duration::ZERO),
                    );
                    call.tracker().on_execution_start();
                    let result = admit_and_perform(&interceptor, function, reach)
                        .unwrap_or_else(ExtFunctionResult::from);
                    call.tracker().on_execution_stop();
                    let writer =
                        PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES));
                    if expired(deadline) {
                        call.abort(deadline_exceeded(), writer)
                    } else {
                        call.resume(result, writer)
                    }
                }
                RunProgress::FunctionCall(call) if call.function_name == FETCH_NAME => {
                    let Some(routing) = egress else {
                        eprintln!(
                            "strands-box: monty fetch refused (no egress): principal=agent function={}",
                            call.function_name
                        );
                        return PythonOutcome {
                            status: BROKER_FAILURE_STATUS,
                            stdout: std::mem::take(&mut captured),
                            stderr: "this box's Python (Monty) has no network without egress\n"
                                .to_string(),
                        };
                    };
                    call.tracker().on_execution_start();
                    let result = recorder
                        .request_context()
                        .scope(fetch_through_gateway(routing, &call.args))
                        .await;
                    call.tracker().on_execution_stop();
                    let writer =
                        PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES));
                    if expired(deadline) {
                        call.abort(deadline_exceeded(), writer)
                    } else {
                        call.resume(result, writer)
                    }
                }
                RunProgress::FunctionCall(call) => {
                    let writer =
                        PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES));
                    let not_found = ExtFunctionResult::NotFound(call.function_name.clone());
                    call.resume(not_found, writer)
                }
                RunProgress::NameLookup(lookup) => {
                    let writer =
                        PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES));
                    lookup.resume(NameLookupResult::Undefined, writer)
                }
                RunProgress::ResolveFutures(_) => Err(MontyException::new(
                    ExcType::RuntimeError,
                    Some("async is not supported by this box's Python (Monty)".to_string()),
                )),
            };
            progress = match stepped {
                Ok(progress) => progress,
                Err(exception) => return raised(&exception, &mut captured),
            };
        }
    };
    match deadline {
        Some(deadline) => match tokio::time::timeout_at(deadline, execution).await {
            Ok(outcome) => outcome,
            Err(_) => raised(&deadline_exceeded(), &mut captured),
        },
        None => execution.await,
    }
}

fn expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

fn deadline_exceeded() -> MontyException {
    MontyException::new(
        ExcType::TimeoutError,
        Some("Python script exceeded its deadline".to_string()),
    )
}

fn sleep_delay(call: &OsFunctionCall) -> Option<Duration> {
    match call {
        OsFunctionCall::Sleep(delay)
        | OsFunctionCall::SystemSleep(delay)
        | OsFunctionCall::AsyncSleep(delay)
        | OsFunctionCall::AsyncSystemSleep(delay) => Some(*delay),
        _ => None,
    }
}

fn abort(
    progress: RunProgress,
    exception: MontyException,
    writer: PrintWriter<'_>,
) -> MontyException {
    let result = match progress {
        RunProgress::OsCall(call) => call.abort(exception, writer),
        RunProgress::FunctionCall(call) => call.abort(exception, writer),
        RunProgress::NameLookup(lookup) => lookup.abort(exception, writer),
        RunProgress::ResolveFutures(futures) => futures.abort(exception, writer),
        RunProgress::Complete(_) => return exception,
    };
    result.err().unwrap_or_else(|| {
        MontyException::new(
            ExcType::RuntimeError,
            Some("an aborted script continued".to_string()),
        )
    })
}

fn raised(exception: &MontyException, captured: &mut String) -> PythonOutcome {
    PythonOutcome {
        status: SCRIPT_RAISED_STATUS,
        stdout: std::mem::take(captured),
        stderr: format!(
            "{}: {}\n(this box's Python is Monty, a subset — see the box's docs)\n",
            exception.exc_type(),
            exception.message().unwrap_or_default()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::record::config::limits::DEFAULT_PYTHON_TIMEOUT;

    use std::path::{Path, PathBuf};

    use policy::Policy;

    use crate::test_support::open_policy;

    /// A box home, one bind, and the reachable set over them, all canonical.
    pub(super) fn fixture() -> (tempfile::TempDir, Reach) {
        let root = tempfile::tempdir().expect("a fixture root");
        let resolved = root.path().canonicalize().expect("the root resolves");
        std::fs::create_dir(resolved.join("home")).expect("the box home");
        std::fs::create_dir(resolved.join("my-service")).expect("the workspace");
        let reach =
            Reach::over(&resolved.join("home"), None, None).expect("the reachable set is usable");
        (root, reach)
    }

    /// A policy that allows every request, so the *floor* is what any refusal below proves.
    pub(super) fn permissive() -> PolicyEngine {
        open_policy(vec![Policy {
            origin: PathBuf::from("<test>"),
            text: "permit(principal, action, resource);".to_string(),
        }])
    }

    /// An undefined name (a `NameLookup`) is a language error, not a broker failure: it raises a
    /// catchable `NameError` and the script exits `1`, the same as CPython.
    #[tokio::test]
    async fn an_undefined_name_raises_a_name_error() {
        let (_root, reach) = fixture();
        let policy = permissive();

        let outcome = run_python(
            "undefined_name".to_string(),
            &reach,
            &policy,
            &GovernedBox::assigned("codex"),
            None,
            &DecisionRecorder::discarding(),
            Some(DEFAULT_PYTHON_TIMEOUT),
        )
        .await;

        assert_eq!(
            outcome.status, SCRIPT_RAISED_STATUS,
            "an undefined name is a Python error, not a broker failure"
        );
        assert!(
            outcome.stderr.contains("NameError"),
            "the script sees a NameError: status={} stderr={}",
            outcome.status,
            outcome.stderr
        );
    }

    /// The raised `NameError` is a real Python exception the script can catch: a `try`/`except`
    /// around an undefined name resumes and the run completes at status `0`.
    #[tokio::test]
    async fn a_caught_name_error_lets_the_script_continue() {
        let (_root, reach) = fixture();
        let policy = permissive();

        let outcome = run_python(
            "try:\n    undefined_name\nexcept NameError:\n    print(\"caught\")\n".to_string(),
            &reach,
            &policy,
            &GovernedBox::assigned("codex"),
            None,
            &DecisionRecorder::discarding(),
            Some(DEFAULT_PYTHON_TIMEOUT),
        )
        .await;

        assert_eq!(
            outcome.status, 0,
            "a caught NameError is not fatal: status={} stderr={}",
            outcome.status, outcome.stderr
        );
        assert!(
            outcome.stdout.contains("caught"),
            "the except branch ran: stdout={}",
            outcome.stdout
        );
    }

    /// Run one script with no egress under `policy`.
    pub(super) async fn run_script(source: &str, policy: &PolicyEngine) -> PythonOutcome {
        run_script_with_timeout(source, policy, Some(DEFAULT_PYTHON_TIMEOUT)).await
    }

    async fn run_script_with_timeout(
        source: &str,
        policy: &PolicyEngine,
        timeout: Option<Duration>,
    ) -> PythonOutcome {
        let (_root, reach) = fixture();
        run_python(
            source.to_string(),
            &reach,
            policy,
            &GovernedBox::assigned("bounds"),
            None,
            &DecisionRecorder::discarding(),
            timeout,
        )
        .await
    }

    fn run_script_with_watchdog(source: &'static str, timeout: Duration) -> PythonOutcome {
        let (finished, result) = std::sync::mpsc::channel();
        let _worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("the script runtime starts");
            let outcome = runtime.block_on(async {
                run_script_with_timeout(source, &permissive(), Some(timeout)).await
            });
            let _ = finished.send(outcome);
        });
        result
            .recv_timeout(Duration::from_secs(5))
            .expect("Python must finish within the independent five-second test watchdog")
    }

    async fn run_script_in(source: &str, policy: &PolicyEngine, reach: &Reach) -> PythonOutcome {
        run_python(
            source.to_string(),
            reach,
            policy,
            &GovernedBox::assigned("bounds"),
            None,
            &DecisionRecorder::discarding(),
            Some(DEFAULT_PYTHON_TIMEOUT),
        )
        .await
    }

    #[tokio::test]
    async fn a_script_stops_at_its_suspension_limit() {
        let outcome = run_script(
            &format!(
                "import os\ntry:\n    for _ in range({}):\n        os.urandom(1)\nexcept Exception:\n    print('caught')",
                SUSPENSION_LIMIT + 1
            ),
            &permissive(),
        )
        .await;
        assert_eq!(outcome.status, SCRIPT_RAISED_STATUS, "{}", outcome.stdout);
        assert!(
            outcome.stderr.contains("RuntimeError"),
            "{}",
            outcome.stderr
        );
        assert!(
            !outcome.stdout.contains("caught"),
            "the limit is not catchable"
        );

        let within = run_script(
            &format!(
                "import os\nfor _ in range({}):\n    os.urandom(1)",
                SUSPENSION_LIMIT
            ),
            &permissive(),
        )
        .await;
        assert_eq!(within.status, 0, "{}", within.stderr);
    }

    #[tokio::test]
    async fn both_sleeps_block_and_concurrent_sleeps_take_the_sum() {
        for source in [
            "import time\nstarted = time.monotonic()\ntime.sleep(0.2)\nprint(time.monotonic() - started >= 0.2)",
            "import asyncio, time\nasync def main():\n    started = time.monotonic()\n    await asyncio.sleep(0.2)\n    return time.monotonic() - started >= 0.2\nprint(asyncio.run(main()))",
            "import asyncio, time\nasync def main():\n    started = time.monotonic()\n    await asyncio.gather(asyncio.sleep(0.2), asyncio.sleep(0.2))\n    return time.monotonic() - started >= 0.4\nprint(asyncio.run(main()))",
        ] {
            let outcome = run_script(source, &open_policy(Vec::new())).await;
            assert_eq!(outcome.status, 0, "{source}: {}", outcome.stderr);
            assert_eq!(outcome.stdout.trim(), "True", "{source}");
        }
    }

    #[tokio::test]
    async fn a_bare_name_resolves_under_the_working_directory() {
        let (_root, reach) = fixture();
        std::fs::write(
            Path::new(reach.working_directory()).join("notes.txt"),
            "from the working directory",
        )
        .expect("the fixture file is written");
        let outcome = run_script_in(
            "import os\nfrom pathlib import Path\nprint(Path('notes.txt').read_text())\nprint(os.getcwd())",
            &permissive(),
            &reach,
        )
        .await;
        assert_eq!(outcome.status, 0, "{}", outcome.stderr);
        assert_eq!(
            outcome.stdout,
            format!(
                "from the working directory\n{}\n",
                reach.working_directory()
            )
        );
    }

    #[tokio::test]
    async fn an_oversized_allocation_stops_the_script_and_not_the_box() {
        let policy = permissive();
        let outcome = run_script(
            &format!(
                "try:\n    b'a' * {}\nexcept MemoryError:\n    print('caught')",
                SCRIPT_MAX_ALLOCATION + 1
            ),
            &policy,
        )
        .await;
        assert_eq!(outcome.status, SCRIPT_RAISED_STATUS, "{}", outcome.stdout);
        assert!(outcome.stderr.contains("MemoryError"), "{}", outcome.stderr);
        assert!(
            !outcome.stdout.contains("caught"),
            "the limit is not catchable"
        );

        let after = run_script("print('still serving')", &policy).await;
        assert_eq!(after.stdout.trim(), "still serving");
    }

    #[test]
    fn a_computing_script_cannot_catch_its_timeout_and_keeps_prior_output() {
        let outcome = run_script_with_watchdog(
            "print('started')\ntry:\n    while True:\n        pass\nexcept Exception:\n    print('caught')",
            Duration::from_millis(100),
        );
        assert_eq!(outcome.status, SCRIPT_RAISED_STATUS);
        assert!(
            outcome.stderr.contains("TimeoutError"),
            "{}",
            outcome.stderr
        );
        assert_eq!(outcome.stdout, "started\n");
    }

    #[test]
    fn sleep_and_resumed_computation_share_one_budget() {
        let started = std::time::Instant::now();
        let outcome = run_script_with_watchdog(
            "import time\nprint('started')\ntime.sleep(1.5)\nwhile True:\n    pass",
            Duration::from_secs(2),
        );
        assert_eq!(outcome.status, SCRIPT_RAISED_STATUS);
        assert!(
            outcome.stderr.contains("TimeoutError"),
            "{}",
            outcome.stderr
        );
        assert_eq!(outcome.stdout, "started\n");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the VM must not receive a fresh budget after sleeping"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn output_and_suspensions_do_not_renew_the_deadline() {
        let started = Instant::now();
        let outcome = run_script_with_timeout(
            "import time\nprint('started')\ntime.sleep(1)\nprint('resumed')\ntry:\n    time.sleep(2)\nexcept Exception:\n    print('caught')\nprint('late')",
            &permissive(),
            Some(Duration::from_secs(2)),
        )
        .await;
        assert_eq!(outcome.status, SCRIPT_RAISED_STATUS);
        assert!(
            outcome.stderr.contains("TimeoutError"),
            "{}",
            outcome.stderr
        );
        assert_eq!(outcome.stdout, "started\nresumed\n");
        assert_eq!(started.elapsed(), Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn configured_and_disabled_timeouts_replace_the_old_sleep_caps() {
        for timeout in [Some(Duration::from_secs(600)), None] {
            let started = Instant::now();
            let outcome = run_script_with_timeout(
                "import time\ntime.sleep(181)\nprint('finished')",
                &permissive(),
                timeout,
            )
            .await;
            assert_eq!(outcome.status, 0, "{}", outcome.stderr);
            assert_eq!(outcome.stdout, "finished\n");
            assert_eq!(started.elapsed(), Duration::from_secs(181));
        }
        let outcome = run_script_with_timeout(
            "import time\ntime.sleep(3601)\nprint('finished')",
            &permissive(),
            None,
        )
        .await;
        assert_eq!(outcome.status, 0, "{}", outcome.stderr);
        assert_eq!(outcome.stdout, "finished\n");
    }

    #[tokio::test(start_paused = true)]
    async fn the_default_budget_includes_sleep_and_each_call_starts_fresh() {
        let policy = permissive();
        let outcome = run_script("import time\ntime.sleep(121)\nprint('late')", &policy).await;
        assert_eq!(outcome.status, SCRIPT_RAISED_STATUS);
        assert!(
            outcome.stderr.contains("TimeoutError"),
            "{}",
            outcome.stderr
        );
        assert!(outcome.stdout.is_empty());
        let next = run_script("import time\ntime.sleep(119)\nprint('finished')", &policy).await;
        assert_eq!(next.status, 0, "{}", next.stderr);
        assert_eq!(next.stdout, "finished\n");
    }

    #[tokio::test(start_paused = true)]
    async fn unlimited_python_still_observes_the_remaining_enclosing_deadline() {
        let deadline = Instant::now() + Duration::from_secs(3);
        tokio::time::sleep(Duration::from_secs(2)).await;
        let outcome = CALL_DEADLINE
            .scope(
                Some(deadline),
                run_script_with_timeout(
                    "import time\ntime.sleep(2)\nprint('late')",
                    &permissive(),
                    None,
                ),
            )
            .await;
        assert_eq!(outcome.status, SCRIPT_RAISED_STATUS);
        assert!(
            outcome.stderr.contains("TimeoutError"),
            "{}",
            outcome.stderr
        );
        assert!(outcome.stdout.is_empty());
        assert_eq!(Instant::now(), deadline);
    }
}
