use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use strands_shell::{EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, Shell};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Intercepted(String),
    OutcomeRecorded(i32),
    Indeterminate,
}

struct RecordingInterceptor {
    events: Arc<Mutex<Vec<Event>>>,
    intercept_error: Option<io::ErrorKind>,
    fail_record: bool,
    record_delay: Option<Duration>,
}

#[async_trait]
impl EffectInterceptor for RecordingInterceptor {
    async fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let EffectAttempt::ShellRun { command, .. } = effect else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsupported effect",
            ));
        };
        self.events
            .lock()
            .unwrap()
            .push(Event::Intercepted((*command).to_string()));
        if let Some(kind) = self.intercept_error {
            let message = if kind == io::ErrorKind::PermissionDenied {
                "test policy denied command"
            } else {
                "test interceptor unavailable"
            };
            return Err(io::Error::new(kind, message));
        }
        Ok(Box::new(RecordingPermit {
            events: Arc::clone(&self.events),
            fail_record: self.fail_record,
            record_delay: self.record_delay,
        }))
    }
}

struct RecordingPermit {
    events: Arc<Mutex<Vec<Event>>>,
    fail_record: bool,
    record_delay: Option<Duration>,
}

#[async_trait]
impl EffectPermit for RecordingPermit {
    async fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        let EffectOutcome::ShellCommand { reported_status } = outcome else {
            return Err(io::Error::other("unexpected effect outcome"));
        };
        self.events
            .lock()
            .unwrap()
            .push(Event::OutcomeRecorded(reported_status));
        if let Some(delay) = self.record_delay {
            tokio::time::sleep(delay).await;
        }
        if self.fail_record {
            Err(io::Error::other("test outcome sink unavailable"))
        } else {
            Ok(())
        }
    }

    fn mark_indeterminate(self: Box<Self>) {
        self.events.lock().unwrap().push(Event::Indeterminate);
    }
}

fn runtime() -> (tokio::runtime::Runtime, tokio::task::LocalSet) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    (runtime, tokio::task::LocalSet::new())
}

#[test]
fn denial_happens_before_command_execution() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let interceptor = Arc::new(RecordingInterceptor {
        events: Arc::clone(&events),
        intercept_error: Some(io::ErrorKind::PermissionDenied),
        fail_record: false,
        record_delay: None,
    });
    let (runtime, local) = runtime();

    runtime.block_on(local.run_until(async {
        let mut shell = Shell::builder()
            .effect_interceptor(interceptor)
            .build()
            .unwrap();
        let output = shell.run("export BLOCKED_EFFECT=ran").await;

        assert_eq!(output.status, 126);
        assert!(output.stderr.contains("effect denied"));
        assert_eq!(shell.get_env("BLOCKED_EFFECT"), None);
    }));
    assert_eq!(
        *events.lock().unwrap(),
        [Event::Intercepted("export BLOCKED_EFFECT=ran".to_string())]
    );
}

#[test]
fn run_and_execute_both_record_their_reported_status() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let interceptor = Arc::new(RecordingInterceptor {
        events: Arc::clone(&events),
        intercept_error: None,
        fail_record: false,
        record_delay: None,
    });
    let (runtime, local) = runtime();

    runtime.block_on(local.run_until(async {
        let mut shell = Shell::builder()
            .effect_interceptor(interceptor)
            .build()
            .unwrap();
        let output = shell.run("false").await;
        assert_eq!(output.status, 1);
        assert_eq!(shell.execute("true").await, 0);
    }));
    assert_eq!(
        *events.lock().unwrap(),
        [
            Event::Intercepted("false".to_string()),
            Event::OutcomeRecorded(1),
            Event::Intercepted("true".to_string()),
            Event::OutcomeRecorded(0),
        ]
    );
}

#[test]
fn outcome_failure_is_not_reported_as_a_denial() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let interceptor = Arc::new(RecordingInterceptor {
        events: Arc::clone(&events),
        intercept_error: None,
        fail_record: true,
        record_delay: None,
    });
    let (runtime, local) = runtime();

    runtime.block_on(local.run_until(async {
        let mut shell = Shell::builder()
            .effect_interceptor(interceptor)
            .build()
            .unwrap();
        let output = shell.run("export COMPLETED_EFFECT=ran").await;

        assert_eq!(shell.get_env("COMPLETED_EFFECT"), Some("ran"));
        assert_eq!(output.status, 125);
        assert!(output.stderr.contains("command completed with status 0"));
        assert!(output.stderr.contains("outcome recording failed"));
        assert!(!output.stderr.contains("effect denied"));
    }));
    assert_eq!(
        *events.lock().unwrap(),
        [
            Event::Intercepted("export COMPLETED_EFFECT=ran".to_string()),
            Event::OutcomeRecorded(0),
        ]
    );
}

#[test]
fn interceptor_failure_is_distinct_from_denial() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let interceptor = Arc::new(RecordingInterceptor {
        events: Arc::clone(&events),
        intercept_error: Some(io::ErrorKind::ConnectionRefused),
        fail_record: false,
        record_delay: None,
    });
    let (runtime, local) = runtime();

    runtime.block_on(local.run_until(async {
        let mut shell = Shell::builder()
            .effect_interceptor(interceptor)
            .build()
            .unwrap();
        let output = shell.run("export FAILED_INTERCEPTOR=ran").await;

        assert_eq!(output.status, 125);
        assert!(output.stderr.contains("effect interception failed"));
        assert!(!output.stderr.contains("effect denied"));
        assert_eq!(shell.get_env("FAILED_INTERCEPTOR"), None);
    }));
    assert_eq!(
        *events.lock().unwrap(),
        [Event::Intercepted(
            "export FAILED_INTERCEPTOR=ran".to_string()
        )]
    );
}

#[test]
fn cancelled_command_marks_its_permit_indeterminate_once() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let interceptor = Arc::new(RecordingInterceptor {
        events: Arc::clone(&events),
        intercept_error: None,
        fail_record: false,
        record_delay: None,
    });
    let (runtime, local) = runtime();

    runtime.block_on(local.run_until(async {
        let mut shell = Shell::builder()
            .effect_interceptor(interceptor)
            .build()
            .unwrap();
        let result = tokio::time::timeout(Duration::from_millis(10), shell.run("sleep 1")).await;
        assert!(result.is_err());
    }));
    assert_eq!(
        *events.lock().unwrap(),
        [
            Event::Intercepted("sleep 1".to_string()),
            Event::Indeterminate,
        ]
    );
}

#[test]
fn cancelled_outcome_recording_is_not_reclassified_as_indeterminate() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let interceptor = Arc::new(RecordingInterceptor {
        events: Arc::clone(&events),
        intercept_error: None,
        fail_record: false,
        record_delay: Some(Duration::from_secs(1)),
    });
    let (runtime, local) = runtime();

    runtime.block_on(local.run_until(async {
        let mut shell = Shell::builder()
            .effect_interceptor(interceptor)
            .build()
            .unwrap();
        let result = tokio::time::timeout(Duration::from_millis(10), shell.run("true")).await;
        assert!(result.is_err());
    }));
    assert_eq!(
        *events.lock().unwrap(),
        [
            Event::Intercepted("true".to_string()),
            Event::OutcomeRecorded(0),
        ]
    );
}
