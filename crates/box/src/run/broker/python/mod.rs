//! Python, as one interpreter behind the box's one broker socket. Monty is the implementation.
//!
//! No listener and no protocol of its own: `run::broker::host` dispatches an
//! `Interpreter::Python` Call here. The interpreter is stateless per Call, which is why this is a
//! function rather than a host.

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

use crate::run::broker::protocol::MAX_CAPTURE_STREAM_BYTES as MAX_SCRIPT_CAPTURE_BYTES;
use crate::run::broker::reach::Reach;
use crate::run::broker::shell::EgressRouting;
use crate::run::telemetry::DecisionRecorder;
use effects::{MontyPep, admit_and_perform};
use fetch::{FETCH_NAME, fetch_through_gateway};

/// Bound on one script's execution time, enforced **inside** the interpreter.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Bound on one allocation of a script, enforced inside the interpreter.
const SCRIPT_MAX_ALLOCATION: usize = 128 * 1024 * 1024;

/// Outer bound on serving one request, around the tracker.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(305);

/// Bound on all the sleeps of one script.
const SLEEP_TOTAL_LIMIT: Duration = Duration::from_secs(180);

/// Bound on the suspensions one script may make.
const SUSPENSION_LIMIT: usize = 10_000;

const _: () = assert!(
    REQUEST_TIMEOUT.as_nanos() > SCRIPT_TIMEOUT.as_nanos(),
    "the outer bound must outlast the interpreter's, or a script stopped at its own deadline is \
     reported as a broker failure"
);

// When Monty is reached through the Shell's `python` command, it runs under the transport's hard
// `SERVE_REQUEST_TIMEOUT` rather than `run_python`'s outer wrap — the seam calls `drive_monty`
// directly (docs/design/decisions.md#python-in-the-shell-is-monty). So each bound below must fire
// *before* the transport's hard kill, or a wedged script reports the transport's generic "call
// exceeded its deadline" instead of its own message.
const _: () = assert!(
    SCRIPT_TIMEOUT.as_nanos() < super::host::SERVE_REQUEST_TIMEOUT.as_nanos(),
    "Monty's in-VM script timeout must be shorter than the transport's request timeout, so a \
     Shell `python` reports Monty's own deadline rather than the transport's generic kill"
);

const _: () = assert!(
    SLEEP_TOTAL_LIMIT.as_nanos() < super::host::SERVE_REQUEST_TIMEOUT.as_nanos(),
    "the sleep bound must fire before the transport's request timeout"
);

/// Compile and run one script, servicing every suspension through policy.
pub(super) async fn run_python(
    source: String,
    reach: &Reach,
    policy: &PolicyEngine,
    governed: &GovernedBox,
    egress: Option<&EgressRouting>,
    recorder: &Arc<DecisionRecorder>,
) -> PythonOutcome {
    // The origin is a diagnostic label in a traceback, never a path this opens.
    match tokio::time::timeout(
        REQUEST_TIMEOUT,
        drive_monty(
            source,
            PYTHON_ORIGIN.to_string(),
            reach,
            policy,
            governed,
            egress,
            recorder,
        ),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => PythonOutcome {
            status: BROKER_FAILURE_STATUS,
            stdout: String::new(),
            stderr: "Python script exceeded its deadline\n".to_string(),
        },
    }
}

/// The status reported when the broker itself failed, rather than the script.
const BROKER_FAILURE_STATUS: i32 = 125;
/// The status reported when a script raised an uncaught exception.
const SCRIPT_RAISED_STATUS: i32 = 1;

/// One Python Call's result: a status and whatever it wrote.
pub(super) struct PythonOutcome {
    pub(super) status: i32,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

/// The origin a traceback names for source that arrived over the wire.
pub(super) const PYTHON_ORIGIN: &str = "<box>";

/// Drive Monty over one script to completion, servicing every suspension through policy.
///
/// This is the un-wrapped inner run: it applies Monty's own `SCRIPT_TIMEOUT` through
/// `ResourceTracker`, but **not** the outer `REQUEST_TIMEOUT`. The direct program path reaches it
/// through [`run_python`], which adds that wrap; the Shell `python` command calls this
/// directly, so on that path the transport's `SERVE_REQUEST_TIMEOUT` is the hard backstop and
/// Monty's in-VM deadline is what a wedged script reports.
pub(super) async fn drive_monty(
    source: String,
    origin: String,
    reach: &Reach,
    policy: &PolicyEngine,
    governed: &GovernedBox,
    egress: Option<&EgressRouting>,
    recorder: &Arc<DecisionRecorder>,
) -> PythonOutcome {
    // **The same reporting as the Shell, or one `context.input.path` means two things.** Without
    // this, a Python `fs:*` request carried the host path while the Shell reported `~/<relative>` —
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
    // `CollectString` with a byte cap rather than a buffer this module grows: the workload
    // chooses how much a script prints, so the writer enforces the cap. Exceeding it raises
    let mut captured = String::new();

    let run = match MontyRun::new(source, &origin, Vec::new(), CompileOptions::default()) {
        Ok(mut run) => {
            run.set_cwd(reach.working_directory());
            run.with_os_policy(OsPolicy {
                sleep: SleepMode::System(Duration::from_secs_f64(MAX_SLEEP_SECONDS)),
                ..OsPolicy::default()
            })
        }
        Err(exception) => return raised(&exception, String::new()),
    };
    // The VM enforces the execution time, and the loop below enforces the suspension and sleep
    // bounds (docs/design/decisions.md#monty-is-per-request-and-buffers-its-output).
    let tracker = ResourceTracker::new(
        ResourceLimits::default()
            .max_feed_duration(SCRIPT_TIMEOUT)
            .max_memory(SCRIPT_MAX_ALLOCATION)
            .max_suspensions(SUSPENSION_LIMIT)
            .max_total_sleep(SLEEP_TOTAL_LIMIT),
    );
    let mut progress = match run.start(
        Vec::new(),
        tracker,
        PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES)),
    ) {
        Ok(progress) => progress,
        Err(exception) => return raised(&exception, String::new()),
    };
    let mut suspensions = 0_usize;
    let mut slept = Duration::ZERO;

    loop {
        if !matches!(progress, RunProgress::Complete(_)) {
            suspensions += 1;
        }
        progress = match progress {
            RunProgress::Complete(_) => {
                return PythonOutcome {
                    status: 0,
                    stdout: captured,
                    stderr: String::new(),
                };
            }
            RunProgress::OsCall(call) if suspensions > call.tracker().max_suspensions() => {
                let writer =
                    PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES));
                let exceeded = suspension_limit_exceeded(call.tracker());
                return raised(&abort_error(call.abort(exceeded, writer)), captured);
            }
            RunProgress::FunctionCall(call) if suspensions > call.tracker().max_suspensions() => {
                let writer =
                    PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES));
                let exceeded = suspension_limit_exceeded(call.tracker());
                return raised(&abort_error(call.abort(exceeded, writer)), captured);
            }
            RunProgress::NameLookup(lookup) if suspensions > lookup.tracker().max_suspensions() => {
                let writer =
                    PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES));
                let exceeded = suspension_limit_exceeded(lookup.tracker());
                return raised(&abort_error(lookup.abort(exceeded, writer)), captured);
            }
            // A sleep is answered without a policy decision, and the box performs the wait.
            RunProgress::OsCall(call) if sleep_delay(&call.function_call).is_some() => {
                let requested =
                    sleep_delay(&call.function_call).expect("the match guard proved a sleep");
                let limit = call
                    .tracker()
                    .max_total_sleep()
                    .unwrap_or(SLEEP_TOTAL_LIMIT);
                let delay = match charge_sleep(&mut slept, requested, limit) {
                    Ok(delay) => delay,
                    Err(exceeded) => {
                        let writer = PrintWriter::CollectString(
                            &mut captured,
                            Some(MAX_SCRIPT_CAPTURE_BYTES),
                        );
                        return raised(&abort_error(call.abort(exceeded, writer)), captured);
                    }
                };
                tokio::time::sleep(delay).await;
                let writer =
                    PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES));
                let stepped = if call.allow_eager_await {
                    call.resume_eager(Ok(MontyObject::none()), writer)
                } else {
                    call.resume(MontyObject::none(), writer)
                };
                match stepped {
                    Ok(next) => next,
                    Err(exception) => return raised(&exception, captured),
                }
            }
            RunProgress::OsCall(call) => {
                // `resume_with` rather than reading `function_call` and resuming separately:
                let writer =
                    PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES));
                let stepped = call.resume_with(writer, |call| {
                    // A denial converts to `ExtFunctionResult::Error`: an ordinary Python
                    // error the script may catch.
                    admit_and_perform(&interceptor, call, reach)
                        .unwrap_or_else(ExtFunctionResult::from)
                });
                match stepped {
                    Ok(next) => next,
                    Err(exception) => return raised(&exception, captured),
                }
            }
            // The one curated network capability. A `fetch(url, method, headers, body)` call
            // arrives here as a `FunctionCall` — a call in call context resolves
            // directly, with no `NameLookup` — carrying its positional `args` and keyword `kwargs`.
            // It is serviced only when the box carries egress. The gateway raises
            // `net:connect`/`http:request`, so this adds no host-side decision.
            RunProgress::FunctionCall(call)
                if egress.is_some() && call.function_name == FETCH_NAME =>
            {
                let routing = egress.expect("the match guard proved egress is present");
                let result = recorder
                    .request_context()
                    .scope(fetch_through_gateway(routing, &call.args))
                    .await;
                let writer =
                    PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES));
                match call.resume(result, writer) {
                    Ok(next) => next,
                    Err(exception) => return raised(&exception, captured),
                }
            }
            // A `fetch` with no egress keeps the network off by absence: fail closed at `125`
            // rather than report it as an undefined name.
            RunProgress::FunctionCall(call) if call.function_name == FETCH_NAME => {
                eprintln!(
                    "strands-box: monty fetch refused (no egress): principal=agent function={}",
                    call.function_name
                );
                return PythonOutcome {
                    status: BROKER_FAILURE_STATUS,
                    stdout: captured,
                    stderr: "this box's Python (Monty) has no network without egress\n".to_string(),
                };
            }
            // Any other unresolved callable is a language error, not a broker failure: resume with
            // `NotFound` so the VM raises a catchable `NameError` and the script exits `1`.
            RunProgress::FunctionCall(call) => {
                let writer =
                    PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES));
                let not_found = ExtFunctionResult::NotFound(call.function_name.clone());
                match call.resume(not_found, writer) {
                    Ok(next) => next,
                    Err(exception) => return raised(&exception, captured),
                }
            }
            // An undefined bare name: resume `Undefined` so the VM raises a catchable `NameError`.
            RunProgress::NameLookup(lookup) => {
                let writer =
                    PrintWriter::CollectString(&mut captured, Some(MAX_SCRIPT_CAPTURE_BYTES));
                match lookup.resume(NameLookupResult::Undefined, writer) {
                    Ok(next) => next,
                    Err(exception) => return raised(&exception, captured),
                }
            }
            // Async is unsupported: report it honestly at status `1`, not as a broker failure.
            RunProgress::ResolveFutures(_) => {
                let exception = MontyException::new(
                    ExcType::RuntimeError,
                    Some("async is not supported by this box's Python (Monty)".to_string()),
                );
                return raised(&exception, captured);
            }
        };
    }
}

/// The wait a sleep call names, or `None` for any other call.
fn sleep_delay(call: &OsFunctionCall) -> Option<Duration> {
    match call {
        OsFunctionCall::Sleep(delay)
        | OsFunctionCall::SystemSleep(delay)
        | OsFunctionCall::AsyncSleep(delay)
        | OsFunctionCall::AsyncSystemSleep(delay) => Some(*delay),
        _ => None,
    }
}

/// Charge one sleep against the script's total, and return the wait to perform.
fn charge_sleep(
    slept: &mut Duration,
    delay: Duration,
    limit: Duration,
) -> Result<Duration, MontyException> {
    if slept.saturating_add(delay) > limit {
        return Err(MontyException::new(
            ExcType::TimeoutError,
            Some(format!(
                "script exceeded its total sleep of {} seconds",
                limit.as_secs()
            )),
        ));
    }
    *slept += delay;
    Ok(delay)
}

fn suspension_limit_exceeded(tracker: &ResourceTracker) -> MontyException {
    MontyException::new(
        ExcType::RuntimeError,
        Some(format!(
            "script exceeded its limit of {} host calls",
            tracker.max_suspensions()
        )),
    )
}

/// The exception an `abort` ends the run with.
fn abort_error(aborted: Result<RunProgress, MontyException>) -> MontyException {
    match aborted {
        Err(exception) => exception,
        Ok(_) => MontyException::new(
            ExcType::RuntimeError,
            Some("an aborted script continued".to_string()),
        ),
    }
}

/// A script that raised, reported the way CPython reports one.
fn raised(exception: &MontyException, captured: String) -> PythonOutcome {
    PythonOutcome {
        status: SCRIPT_RAISED_STATUS,
        stdout: captured,
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

        let outcome = drive_monty(
            "undefined_name".to_string(),
            PYTHON_ORIGIN.to_string(),
            &reach,
            &policy,
            &GovernedBox::assigned("codex"),
            None,
            &DecisionRecorder::discarding(),
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

        let outcome = drive_monty(
            "try:\n    undefined_name\nexcept NameError:\n    print(\"caught\")\n".to_string(),
            PYTHON_ORIGIN.to_string(),
            &reach,
            &policy,
            &GovernedBox::assigned("codex"),
            None,
            &DecisionRecorder::discarding(),
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
        let (_root, reach) = fixture();
        run_script_in(source, policy, &reach).await
    }

    async fn run_script_in(source: &str, policy: &PolicyEngine, reach: &Reach) -> PythonOutcome {
        drive_monty(
            source.to_string(),
            PYTHON_ORIGIN.to_string(),
            reach,
            policy,
            &GovernedBox::assigned("bounds"),
            None,
            &DecisionRecorder::discarding(),
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

    #[tokio::test]
    async fn a_sleep_longer_than_the_total_raises_at_once() {
        let started = std::time::Instant::now();
        let outcome = run_script(
            "import time\ntime.sleep(600)\nprint('woke')",
            &open_policy(Vec::new()),
        )
        .await;
        assert_eq!(outcome.status, SCRIPT_RAISED_STATUS, "{}", outcome.stdout);
        assert!(
            outcome.stderr.contains("TimeoutError"),
            "{}",
            outcome.stderr
        );
        assert!(!outcome.stdout.contains("woke"));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_sleep_is_never_shortened_and_the_total_is_bounded() {
        let mut slept = Duration::ZERO;
        assert_eq!(
            charge_sleep(&mut slept, SLEEP_TOTAL_LIMIT, SLEEP_TOTAL_LIMIT).ok(),
            Some(SLEEP_TOTAL_LIMIT),
            "one sleep may use the whole total"
        );
        slept = Duration::ZERO;
        let refused = charge_sleep(&mut slept, Duration::from_secs(600), SLEEP_TOTAL_LIMIT)
            .expect_err("a sleep longer than the total is refused, not shortened");
        assert_eq!(refused.exc_type(), ExcType::TimeoutError);
        assert_eq!(slept, Duration::ZERO, "a refused sleep is not charged");
        slept = SLEEP_TOTAL_LIMIT - Duration::from_secs(1);
        assert_eq!(
            charge_sleep(&mut slept, Duration::from_secs(1), SLEEP_TOTAL_LIMIT).ok(),
            Some(Duration::from_secs(1))
        );
        let refused = charge_sleep(&mut slept, Duration::from_millis(1), SLEEP_TOTAL_LIMIT)
            .expect_err("the total is spent");
        assert_eq!(refused.exc_type(), ExcType::TimeoutError);
        assert_eq!(slept, SLEEP_TOTAL_LIMIT);
    }
}
