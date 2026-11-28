use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use crate::delivery::{Delivery, configured_endpoint};
use crate::{
    ActionCatalog, CoreOutcome, DecisionInterval, Event, ExitOutcome, Invocation, Journal,
    LaunchOutcome, POLLING_INTERVAL, Polling, Record,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// The longest the CLI waits for final telemetry at any exit.
pub const COMPLETION_BUDGET: Duration = Duration::from_secs(2);

/// Event collection for one invocation.
pub struct Session {
    commands: Sender<Command>,
    finished: Receiver<()>,
    observing: bool,
    #[cfg(test)]
    started: Instant,
}

enum Command {
    Observe(Box<Observation>),
    CoreFailureCode(&'static str),
    Finish(Instant, ExitOutcome, Option<Instant>),
}

struct Observation {
    journal: Journal,
    interval: DecisionInterval,
    next: Instant,
    /// `Confirmed` once Core recorded that the workload started, which ends startup.
    launch: LaunchOutcome,
    core_outcome: Option<CoreOutcome>,
}

impl Session {
    /// Capture and send events through one background worker.
    pub fn delivering(invocation: Invocation, outcome: LaunchOutcome) -> Option<Self> {
        let endpoint = configured_endpoint()?;
        Some(Self::deliver_to(
            invocation,
            outcome,
            endpoint,
            REQUEST_TIMEOUT,
        ))
    }

    fn deliver_to(
        invocation: Invocation,
        outcome: LaunchOutcome,
        endpoint: String,
        timeout: Duration,
    ) -> Self {
        let user_agent = invocation.user_agent();
        Self::start_with(invocation, outcome, move || {
            let delivery = Delivery::new(endpoint, timeout, &user_agent)?;
            Some(move |events: Vec<Event>, deadline: Option<Instant>| {
                delivery.send_all(&events, deadline);
            })
        })
    }

    /// Start capture with a callback that bounds its own work.
    pub fn start(
        invocation: Invocation,
        outcome: LaunchOutcome,
        emit: impl Fn(Event) + Send + 'static,
    ) -> Self {
        Self::start_with(invocation, outcome, move || {
            Some(move |events: Vec<Event>, _: Option<Instant>| events.into_iter().for_each(&emit))
        })
    }

    fn start_with<F: Fn(Vec<Event>, Option<Instant>) + Send + 'static>(
        invocation: Invocation,
        outcome: LaunchOutcome,
        factory: impl FnOnce() -> Option<F> + Send + 'static,
    ) -> Self {
        let (commands, pending) = mpsc::channel();
        let (done, finished) = mpsc::channel();
        #[cfg(test)]
        let started = invocation.started();
        let _ = std::thread::Builder::new()
            .name("box-telemetry".into())
            .spawn(move || {
                let Some(emit) = factory() else {
                    return;
                };
                let _ = catch_unwind(AssertUnwindSafe(|| {
                    capture(invocation, outcome, pending, &emit);
                }));
                let _ = done.send(());
            });
        Self {
            commands,
            finished,
            observing: false,
            #[cfg(test)]
            started,
        }
    }

    /// Report the message code of the failure that ended Core's run, such as `B0114`, or
    /// `uncoded` for a Box defect. The shutdown event carries it; call it before `finish`.
    pub fn core_failure_code(&self, code: &'static str) {
        let _ = self.commands.send(Command::CoreFailureCode(code));
    }

    /// Observe the journal while the caller retains the box's instance lock.
    pub fn observe(&mut self, journal: Journal, catalog: ActionCatalog) {
        self.observe_from(journal, catalog, Instant::now());
    }

    fn observe_from(&mut self, journal: Journal, catalog: ActionCatalog, started: Instant) {
        if !self.observing {
            self.observing = true;
            let _ = self
                .commands
                .send(Command::Observe(Box::new(Observation::new(
                    journal, catalog, started,
                ))));
        }
    }

    /// Finish collection and send attempts before the caller releases the instance lock.
    pub fn finish(self, completed: Instant, outcome: ExitOutcome) {
        self.finish_by(completed, outcome, None);
    }

    /// Limit the caller's wait; the journal must retain its instance lock.
    pub fn finish_with_timeout(self, completed: Instant, outcome: ExitOutcome, timeout: Duration) {
        self.finish_by(
            completed,
            outcome,
            Some(completed.checked_add(timeout).unwrap_or(completed)),
        );
    }

    fn finish_by(self, completed: Instant, outcome: ExitOutcome, deadline: Option<Instant>) {
        let _ = self
            .commands
            .send(Command::Finish(completed, outcome, deadline));
        if let Some(deadline) = deadline {
            let _ = self
                .finished
                .recv_timeout(deadline.saturating_duration_since(Instant::now()));
        } else {
            let _ = self.finished.recv();
        }
    }
}

fn capture(
    invocation: Invocation,
    outcome: LaunchOutcome,
    commands: Receiver<Command>,
    emit: &dyn Fn(Vec<Event>, Option<Instant>),
) {
    let mut run_sent = false;
    let mut core_failure_code = None;
    let mut observation: Option<Box<Observation>> = None;
    loop {
        match commands.recv_timeout(Duration::from_secs(1)) {
            Ok(Command::Observe(observed)) => observation = Some(observed),
            Ok(Command::CoreFailureCode(code)) => core_failure_code = Some(code),
            Ok(Command::Finish(completed, exit, deadline)) => {
                let expired = || deadline.is_some_and(|deadline| Instant::now() >= deadline);
                if expired() {
                    return;
                }
                let final_interval = observation
                    .as_mut()
                    .and_then(|item| item.finish(completed, deadline));
                let launch = observation.as_ref().map_or(outcome, |item| item.launch);
                let core_outcome = observation.as_ref().and_then(|item| item.core_outcome);
                drop(observation.take());
                if expired() {
                    return;
                }
                let mut events = Vec::with_capacity(3);
                if !run_sent {
                    events.push(invocation.run_event(launch));
                }
                if let Some(interval) = final_interval {
                    events.push(invocation.polling_event(interval));
                }
                events.push(invocation.shutdown_event(
                    completed,
                    exit,
                    core_outcome,
                    core_failure_code,
                ));
                emit(events, deadline);
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Some(observation) = observation.as_mut() {
                    let polling = observation.tick(Instant::now());
                    let mut events = Vec::new();
                    if !run_sent && matches!(observation.launch, LaunchOutcome::Confirmed(_)) {
                        run_sent = true;
                        events.push(invocation.run_event(observation.launch));
                    }
                    if let Some(polling) = polling {
                        events.push(invocation.polling_event(polling));
                    }
                    if !events.is_empty() {
                        emit(events, None);
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

impl Observation {
    fn new(journal: Journal, catalog: ActionCatalog, started: Instant) -> Self {
        Self {
            journal,
            interval: DecisionInterval::new(started, catalog),
            next: started + POLLING_INTERVAL,
            launch: LaunchOutcome::Unknown,
            core_outcome: None,
        }
    }

    fn read(&mut self) {
        self.journal.read(|record| match record {
            Record::WorkloadStarted(started_at) => {
                if matches!(self.launch, LaunchOutcome::Unknown) {
                    self.launch = LaunchOutcome::Confirmed(started_at);
                }
            }
            Record::BoxStopped(outcome) => self.core_outcome = Some(outcome),
            Record::Decision(decision) => self.interval.observe(decision),
        });
    }

    fn tick(&mut self, now: Instant) -> Option<Polling> {
        self.read();
        if now < self.next {
            return None;
        }
        self.next = now + POLLING_INTERVAL;
        self.interval.finish(now, self.journal.finish_interval())
    }

    fn finish(&mut self, completed: Instant, deadline: Option<Instant>) -> Option<Polling> {
        let deadline = deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(3));
        while Instant::now() < deadline {
            self.read();
            if self.journal.at_end() {
                break;
            }
        }
        self.interval
            .finish(completed, self.journal.finish_interval())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::UNIX_EPOCH;

    use serde_json::{Value, json};

    use super::*;
    use crate::{ContextBuilder, FailureReason, InstallationId};

    struct Service {
        endpoint: String,
        events: Receiver<Value>,
        user_agents: Receiver<String>,
        stop: Arc<AtomicBool>,
        finished: Receiver<()>,
    }

    impl Service {
        fn start(delay: Duration) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let endpoint = format!("http://{}/box/ping", listener.local_addr().unwrap());
            let (emit, events) = mpsc::channel();
            let (agent, user_agents) = mpsc::channel();
            let (done, finished) = mpsc::channel();
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = stop.clone();
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                while !stopping.load(Ordering::SeqCst) && Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            if let Some((body, user_agent)) = read_event(&mut stream) {
                                let _ = agent.send(user_agent.unwrap_or_default());
                                match body {
                                    Value::Array(events) => events.into_iter().for_each(|event| {
                                        let _ = emit.send(event);
                                    }),
                                    event => {
                                        let _ = emit.send(event);
                                    }
                                }
                                std::thread::sleep(delay);
                                let _ = stream.write_all(
                                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                );
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
                let _ = done.send(());
            });
            Self {
                endpoint,
                events,
                user_agents,
                stop,
                finished,
            }
        }

        fn session(&self, outcome: LaunchOutcome, timeout: Duration) -> Session {
            Session::deliver_to(invocation(), outcome, self.endpoint.clone(), timeout)
        }

        fn event(&self) -> Value {
            self.events.recv_timeout(Duration::from_secs(1)).unwrap()
        }
    }

    impl Drop for Service {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            self.finished.recv_timeout(Duration::from_secs(2)).unwrap();
        }
    }

    fn read_event(stream: &mut TcpStream) -> Option<(Value, Option<String>)> {
        stream.set_nonblocking(false).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let mut length = None;
        let mut user_agent = None;
        loop {
            line.clear();
            if reader.read_line(&mut line).ok()? == 0 {
                return None;
            }
            if line == "\r\n" {
                break;
            }
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse::<usize>().ok();
            }
            if name.eq_ignore_ascii_case("user-agent") {
                user_agent = Some(value.trim().to_owned());
            }
        }
        let length = length.filter(|length| *length <= 32 * 1024)?;
        let mut body = vec![0; length];
        reader.read_exact(&mut body).ok()?;
        Some((serde_json::from_slice(&body).ok()?, user_agent))
    }

    fn invocation() -> Invocation {
        let directory = tempfile::tempdir().unwrap();
        let mut context = ContextBuilder::new("1.2.3").unwrap();
        context.profile(b"policies = [\"policy.dw\"]\n");
        Invocation::new(
            InstallationId::load_or_create(directory.path()).unwrap(),
            context.finish(),
            Instant::now(),
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )
        .unwrap()
    }

    fn append(path: &std::path::Path) {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .unwrap();
        writeln!(
            file,
            "{}",
            json!({"resourceLogs":[{
                "resource":{"attributes":[
                    {"key":"service.name","value":{"stringValue":"strands-box"}},
                    {"key":"strands.box.source","value":{"stringValue":"box"}}
                ]},
                "scopeLogs":[{"scope":{"name":"strands-box.policy"},"logRecords":[{
                    "eventName":"strands.box.policy.decision",
                    "attributes":[
                        {"key":"strands.box.policy.action","value":{"stringValue":"fs:read"}},
                        {"key":"strands.box.policy.category","value":{"stringValue":"fs"}},
                        {"key":"strands.box.policy.verdict","value":{"stringValue":"permit"}}
                    ]
                }]}]
            }]})
        )
        .unwrap();
    }

    fn catalog() -> ActionCatalog {
        ActionCatalog::new([])
    }

    fn capture(outcome: LaunchOutcome) -> (Session, Receiver<Value>) {
        let (send, events) = mpsc::channel();
        let session = Session::start(invocation(), outcome, move |event| {
            send.send(serde_json::to_value(event).unwrap()).unwrap();
        });
        (session, events)
    }

    #[test]
    fn callback_panics_do_not_escape_the_session() {
        for fail_on in ["run/1", "shutdown/1"] {
            let (send, events) = mpsc::channel();
            let result = std::panic::catch_unwind(|| {
                let session =
                    Session::start(invocation(), LaunchOutcome::Confirmed(None), move |event| {
                        let event = serde_json::to_value(event).unwrap();
                        let name = event["event"].as_str().unwrap().to_owned();
                        send.send(name.clone()).unwrap();
                        assert_ne!(name, fail_on, "telemetry failure");
                    });
                session.finish(Instant::now(), ExitOutcome::Nonzero);
            });
            assert!(result.is_ok(), "{fail_on} panic reached the caller");
            assert!(events.try_iter().any(|name| name == fail_on));
        }
    }

    #[test]
    fn completion_does_not_wait_for_callback_cleanup() {
        struct Cleanup(Receiver<()>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = self.0.recv_timeout(Duration::from_secs(2));
            }
        }
        let (release, released) = mpsc::channel();
        let cleanup = Cleanup(released);
        let session = Session::start(invocation(), LaunchOutcome::Unknown, move |_| {
            let _ = &cleanup;
        });
        let started = Instant::now();
        session.finish(started, ExitOutcome::Zero);
        let elapsed = started.elapsed();
        let _ = release.send(());
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    }

    #[test]
    fn shutdown_is_attempted_after_a_request_timeout() {
        let service = Service::start(Duration::from_millis(200));
        let session = service.session(LaunchOutcome::Unknown, Duration::from_millis(80));
        session.finish(Instant::now(), ExitOutcome::Zero);
        let mut names = [service.event(), service.event()].map(|event| event["event"].clone());
        names.sort_by_key(|name| name.to_string());
        assert_eq!(names, [json!("run/1"), json!("shutdown/1")]);
    }

    #[test]
    fn completion_deadline_leaves_a_stalled_worker_with_its_journal_lock() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        std::fs::write(&path, "").unwrap();
        let lock_path = directory.path().join("lock");
        let lock = Arc::new(std::fs::File::create(&lock_path).unwrap());
        lock.try_lock().unwrap();
        let journal = Journal::start_locked(&path, lock.clone()).unwrap();
        let (entered, stalled) = mpsc::sync_channel(1);
        let (resume, resumed) = mpsc::sync_channel(1);
        let (sent, events) = mpsc::channel();
        let mut session = Session::start(invocation(), LaunchOutcome::Unknown, move |event| {
            entered.send(()).unwrap();
            resumed.recv_timeout(Duration::from_secs(2)).unwrap();
            sent.send(serde_json::to_value(event).unwrap()).unwrap();
        });
        session.observe(journal, catalog());
        drop(lock);
        append_start(&path);
        stalled.recv_timeout(Duration::from_secs(3)).unwrap();
        let completed = Instant::now();
        session.finish_with_timeout(completed, ExitOutcome::Nonzero, Duration::from_millis(100));
        let elapsed = completed.elapsed();
        let contender = std::fs::File::open(&lock_path).unwrap();
        let held = contender.try_lock().is_err();
        resume.send(()).unwrap();
        // The worker stalls until `resume`, so a wait for it lasts the stall's 2 seconds. A busy
        // runner can wake the 100 ms deadline late, so the bound sits well between the two.
        assert!(
            elapsed < Duration::from_secs(1),
            "completion waited for a stalled request: {elapsed:?}"
        );
        assert!(held, "the worker retains the journal's instance lock");
        assert_eq!(
            events.recv_timeout(Duration::from_secs(1)).unwrap()["event"],
            "run/1"
        );
        assert!(
            matches!(
                events.recv_timeout(Duration::from_secs(1)),
                Err(mpsc::RecvTimeoutError::Disconnected)
            ),
            "the expired budget drops remaining events"
        );
        contender.try_lock().unwrap();
    }

    #[test]
    fn an_expired_completion_budget_does_not_read_the_journal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        std::fs::write(&path, "").unwrap();
        let completed = Instant::now();
        let mut observation =
            Observation::new(Journal::start(&path).unwrap(), catalog(), completed);
        append_control(&path, "box_stopped", "ok", None);
        observation.finish(completed, Some(completed));
        assert_eq!(observation.core_outcome, None);
        observation.finish(completed, None);
        assert_eq!(observation.core_outcome, Some(CoreOutcome::Ok));
    }

    #[test]
    fn final_polling_precedes_shutdown_and_excludes_existing_records() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        append(&path);
        let journal = Journal::start(&path).unwrap();
        let (mut session, events) = capture(LaunchOutcome::Unknown);
        let started = Instant::now();
        let completed = started + Duration::from_millis(4321);
        session.observe_from(journal, catalog(), started);
        append(&path);
        session.finish(completed, ExitOutcome::Zero);
        let run = events.try_recv().unwrap();
        let polling = events.try_recv().unwrap();
        let shutdown = events.try_recv().unwrap();
        assert_eq!(run["event"], "run/1");
        assert_eq!(polling["event"], "polling/1");
        assert_eq!(polling["data"]["interval_duration_ms"], 4321);
        assert_eq!(
            polling["data"]["decisions"],
            json!([{
                "action":"fs:read","outcome":"permitted","count":1
            }])
        );
        assert_eq!(shutdown["event"], "shutdown/1");
        assert_eq!(shutdown["data"]["exit_outcome"], "zero");
        for key in ["installation_id", "run_id", "context"] {
            assert_eq!(run[key], polling[key], "{key}");
            assert_eq!(run[key], shutdown[key], "{key}");
        }
    }

    #[test]
    fn observation_emits_sixty_second_deltas_and_a_final_partial_interval() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        std::fs::write(&path, "").unwrap();
        let start = Instant::now();
        let mut observation = Observation::new(Journal::start(&path).unwrap(), catalog(), start);
        append(&path);
        assert!(observation.tick(start + Duration::from_secs(59)).is_none());
        let first =
            serde_json::to_value(observation.tick(start + Duration::from_secs(60)).unwrap())
                .unwrap();
        assert_eq!(first["interval_duration_ms"], 60_000);
        assert_eq!(first["decisions"][0]["count"], 1);
        append(&path);
        assert!(observation.tick(start + Duration::from_secs(65)).is_none());
        let last = serde_json::to_value(
            observation
                .finish(start + Duration::from_millis(65_500), None)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(last["interval_duration_ms"], 5500);
        assert_eq!(last["decisions"][0]["count"], 1);
    }

    #[test]
    fn worker_publishes_a_periodic_interval_before_completion() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        std::fs::write(&path, "").unwrap();
        let journal = Journal::start(&path).unwrap();
        let (mut session, events) = capture(LaunchOutcome::Unknown);
        session.observe_from(journal, catalog(), Instant::now() - POLLING_INTERVAL);
        append_start(&path);
        append(&path);
        assert_eq!(
            events.recv_timeout(Duration::from_secs(3)).unwrap()["event"],
            "run/1"
        );
        let polling = events.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(polling["event"], "polling/1");
        assert_eq!(polling["data"]["decisions"][0]["count"], 1);
        session.finish(Instant::now(), ExitOutcome::Zero);
        assert_eq!(events.try_recv().unwrap()["event"], "polling/1");
        assert_eq!(events.try_recv().unwrap()["event"], "shutdown/1");
    }

    #[test]
    fn completion_waits_for_the_worker_to_publish_its_periodic_sample() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        std::fs::write(&path, "").unwrap();
        let (send, events) = mpsc::sync_channel(4);
        let (entered, publishing) = mpsc::sync_channel(1);
        let (resume, resumed) = mpsc::sync_channel(1);
        let resumed = Mutex::new(resumed);
        let first_polling = AtomicBool::new(true);
        let mut session = Session::start(invocation(), LaunchOutcome::Unknown, move |event| {
            let event = serde_json::to_value(event).unwrap();
            if event["event"] == "polling/1" && first_polling.swap(false, Ordering::SeqCst) {
                entered.send(()).unwrap();
                resumed
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
            send.send(event).unwrap();
        });
        session.observe_from(
            Journal::start(&path).unwrap(),
            catalog(),
            Instant::now() - POLLING_INTERVAL,
        );
        append_start(&path);
        publishing.recv_timeout(Duration::from_secs(3)).unwrap();
        let (finished, completion) = mpsc::sync_channel(1);
        let finisher = std::thread::spawn(move || {
            session.finish(Instant::now(), ExitOutcome::Zero);
            finished.send(()).unwrap();
        });
        let finished_before_publication =
            completion.recv_timeout(Duration::from_millis(250)).is_ok();
        resume.send(()).unwrap();
        finisher.join().unwrap();
        assert!(
            !finished_before_publication,
            "completion must wait for the periodic callback before it captures shutdown"
        );
        assert_eq!(events.try_recv().unwrap()["event"], "run/1");
        assert_eq!(events.try_recv().unwrap()["event"], "polling/1");
        let remaining: Vec<Value> = events.try_iter().collect();
        assert_eq!(remaining.last().unwrap()["event"], "shutdown/1");
    }

    fn append_start(path: &Path) {
        append_control(path, "box_started", "ok", Some("1700000000000000000"));
        append_control(path, "workload_started", "ok", Some("1700000001234567890"));
    }

    fn append_control(path: &Path, operation: &str, outcome: &str, timestamp: Option<&str>) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(
            file,
            "{}",
            json!({"resourceLogs":[{
                "resource":{"attributes":[
                    {"key":"service.name","value":{"stringValue":"strands-box"}},
                    {"key":"strands.box.source","value":{"stringValue":"box"}}
                ]},
                "scopeLogs":[{"scope":{"name":"strands-box.control"},"logRecords":[{
                    "timeUnixNano":timestamp,
                    "attributes":[
                        {"key":"strands.box.control.operation","value":{"stringValue":operation}},
                        {"key":"strands.box.control.outcome","value":{"stringValue":outcome}}
                    ]
                }]}]
            }]})
        )
        .unwrap();
    }

    fn assert_shutdown(
        events: &Receiver<Value>,
        run: &Value,
        outcome: &str,
        core_outcome: Option<&str>,
    ) -> Value {
        let shutdown = events.try_recv().unwrap();
        assert_eq!(shutdown["event"], "shutdown/1");
        assert_eq!(shutdown["data"]["exit_outcome"], outcome);
        assert!(
            shutdown["data"]
                .as_object()
                .unwrap()
                .contains_key("core_outcome")
        );
        assert_eq!(shutdown["data"]["core_outcome"], json!(core_outcome));
        for field in ["v", "installation_id", "run_id", "context"] {
            assert_eq!(run[field], shutdown[field], "{field}");
        }
        assert!(events.try_recv().is_err());
        shutdown
    }

    fn assert_empty_polling(events: &Receiver<Value>) {
        let polling = events.try_recv().unwrap();
        assert_eq!(polling["event"], "polling/1");
        assert_eq!(polling["data"]["decisions"], json!([]));
    }

    #[test]
    fn preparation_waits_for_startup_and_missing_evidence_stays_unknown() {
        let (session, events) = capture(LaunchOutcome::Unknown);
        assert!(events.try_recv().is_err());
        let completed = session.started + Duration::from_millis(1234);
        session.finish(completed, ExitOutcome::Zero);
        let event = events.try_recv().unwrap();
        assert_eq!(event["event"], "run/1");
        assert_eq!(
            event["data"],
            json!({"box_launched":null,"failure_reason":null,"startup_latency_ms":null})
        );
        let shutdown = assert_shutdown(&events, &event, "zero", None);
        assert_eq!(shutdown["data"]["invocation_duration_ms"], 1234);
    }

    #[test]
    fn preparation_failure_is_sent_once_with_shutdown() {
        let (session, events) = capture(LaunchOutcome::PreparationFailed(
            FailureReason::ProfileMissing,
        ));
        assert!(events.recv_timeout(Duration::from_millis(100)).is_err());
        let completed = session.started + Duration::from_millis(321);
        session.finish(completed, ExitOutcome::Nonzero);
        let event = events.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            event["data"],
            json!({"box_launched":false,"failure_reason":"profile_missing","startup_latency_ms":null})
        );
        let shutdown = assert_shutdown(&events, &event, "nonzero", None);
        assert_eq!(shutdown["data"]["invocation_duration_ms"], 321);
    }

    #[test]
    fn startup_is_captured_before_completion_and_only_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        append_start(&path);
        let (mut session, events) = capture(LaunchOutcome::Unknown);
        session.observe(Journal::start(&path).unwrap(), catalog());
        assert!(events.try_recv().is_err());
        append_start(&path);
        append_control(&path, "box_stopped", "ok", None);
        let event = events.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            event["data"],
            json!({"box_launched":true,"failure_reason":null,"startup_latency_ms":1234})
        );
        append_start(&path);
        session.finish(Instant::now(), ExitOutcome::Nonzero);
        assert_empty_polling(&events);
        assert_shutdown(&events, &event, "nonzero", Some("ok"));
    }

    #[test]
    fn startup_uses_the_first_record_in_a_journal_read() {
        for timestamp in [None, Some("1700000001234567890")] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("records.jsonl");
            let (mut session, events) = capture(LaunchOutcome::Unknown);
            let journal = Journal::start(&path).unwrap();
            append_control(&path, "workload_started", "ok", timestamp);
            append_control(&path, "workload_started", "ok", Some("1700000009876543210"));
            session.observe(journal, catalog());
            session.finish(Instant::now(), ExitOutcome::Zero);
            let run = events.try_recv().unwrap();
            assert_eq!(run["event"], "run/1");
            assert_eq!(run["data"]["box_launched"], true);
            assert_eq!(
                run["data"]["startup_latency_ms"],
                json!(timestamp.map(|_| 1234)),
            );
            assert_empty_polling(&events);
            assert_shutdown(&events, &run, "zero", None);
        }
    }

    #[test]
    fn completion_reads_startup_and_stop_after_a_backlog() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        let (mut session, events) = capture(LaunchOutcome::Unknown);
        session.observe(Journal::start(&path).unwrap(), catalog());
        std::fs::write(&path, b"{}\n".repeat(400_000)).unwrap();
        append_start(&path);
        append_control(&path, "box_stopped", "refused", None);
        session.finish(Instant::now(), ExitOutcome::Nonzero);
        let event = events.try_recv().unwrap();
        assert_eq!(
            event["data"],
            json!({"box_launched":true,"failure_reason":null,"startup_latency_ms":1234})
        );
        assert_empty_polling(&events);
        assert_shutdown(&events, &event, "nonzero", Some("refused"));
    }

    #[test]
    fn old_records_do_not_confirm_this_invocation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        append_start(&path);
        append_control(&path, "box_stopped", "refused", None);
        let (mut session, events) = capture(LaunchOutcome::Unknown);
        session.observe(Journal::start(&path).unwrap(), catalog());
        session.finish(Instant::now(), ExitOutcome::Zero);
        let event = events.try_recv().unwrap();
        assert_eq!(
            event["data"],
            json!({"box_launched":null,"failure_reason":null,"startup_latency_ms":null})
        );
        assert_empty_polling(&events);
        assert_shutdown(&events, &event, "zero", None);
    }

    #[test]
    fn periodic_backlog_keeps_startup_and_excludes_decisions_from_the_old_interval() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        let started = Instant::now();
        let mut observation = Observation::new(Journal::start(&path).unwrap(), catalog(), started);
        std::fs::write(&path, b"{}\n".repeat(400_000)).unwrap();
        append_start(&path);
        append(&path);
        assert!(observation.tick(started + POLLING_INTERVAL).is_none());
        assert!(matches!(observation.launch, LaunchOutcome::Unknown));
        assert!(
            observation
                .tick(started + POLLING_INTERVAL + Duration::from_secs(1))
                .is_none()
        );
        assert!(matches!(observation.launch, LaunchOutcome::Confirmed(_)));
        append(&path);
        let last = serde_json::to_value(
            observation
                .finish(started + POLLING_INTERVAL + Duration::from_secs(2), None)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            last["decisions"],
            json!([{"action":"fs:read","outcome":"permitted","count":1}])
        );
    }

    #[test]
    fn stop_without_startup_preserves_each_events_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        let (mut session, events) = capture(LaunchOutcome::Unknown);
        session.observe(Journal::start(&path).unwrap(), catalog());
        append_control(&path, "box_stopped", "refused", None);
        session.finish(Instant::now(), ExitOutcome::Nonzero);
        let event = events.try_recv().unwrap();
        assert_eq!(
            event["data"],
            json!({"box_launched":null,"failure_reason":null,"startup_latency_ms":null})
        );
        assert_empty_polling(&events);
        assert_shutdown(&events, &event, "nonzero", Some("refused"));
    }

    #[test]
    fn a_box_whose_workload_never_starts_sends_its_run_at_completion_without_launch_or_latency() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        let (mut session, events) = capture(LaunchOutcome::Unknown);
        session.observe(Journal::start(&path).unwrap(), catalog());
        append_control(&path, "box_started", "ok", Some("1700000001234567890"));
        assert!(
            events.recv_timeout(Duration::from_millis(2500)).is_err(),
            "startup is not over until the workload starts"
        );
        append_control(&path, "box_stopped", "refused", None);
        session.finish(Instant::now(), ExitOutcome::Nonzero);
        let event = events.try_recv().unwrap();
        assert_eq!(
            event["data"],
            json!({"box_launched":null,"failure_reason":null,"startup_latency_ms":null})
        );
        assert_empty_polling(&events);
        assert_shutdown(&events, &event, "nonzero", Some("refused"));
    }

    #[test]
    fn startup_without_a_usable_timestamp_still_precedes_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        let (mut session, events) = capture(LaunchOutcome::Unknown);
        session.observe(Journal::start(&path).unwrap(), catalog());
        append_control(&path, "box_started", "ok", None);
        append_control(&path, "workload_started", "ok", None);
        session.finish(Instant::now(), ExitOutcome::Zero);
        let event = events.try_recv().unwrap();
        assert_eq!(
            event["data"],
            json!({"box_launched":true,"failure_reason":null,"startup_latency_ms":null})
        );
        assert_empty_polling(&events);
        assert_shutdown(&events, &event, "zero", None);
    }
    #[test]
    fn delivery_sends_run_final_polling_and_shutdown_with_the_same_envelope() {
        let service = Service::start(Duration::ZERO);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        append(&path);
        let journal = Journal::start(&path).unwrap();
        let mut session = service.session(LaunchOutcome::Unknown, Duration::from_secs(1));
        session.observe(journal, catalog());
        append_start(&path);
        append_control(&path, "box_stopped", "ok", None);
        append(&path);
        session.finish(Instant::now(), ExitOutcome::Zero);
        let received: std::collections::BTreeMap<String, Value> = (0..3)
            .map(|_| {
                let event = service.event();
                (event["event"].as_str().unwrap().to_owned(), event)
            })
            .collect();
        let (run, polling, shutdown) = (
            &received["run/1"],
            &received["polling/1"],
            &received["shutdown/1"],
        );
        assert_eq!(run["data"]["box_launched"], true);
        assert_eq!(
            polling["data"]["decisions"],
            json!([{"action":"fs:read","outcome":"permitted","count":1}])
        );
        assert_eq!(shutdown["event"], "shutdown/1");
        assert_eq!(shutdown["data"]["exit_outcome"], "zero");
        assert_eq!(shutdown["data"]["core_outcome"], "ok");
        for key in ["installation_id", "run_id", "context"] {
            assert_eq!(run[key], polling[key], "{key}");
            assert_eq!(run[key], shutdown[key], "{key}");
        }
        assert!(service.events.try_recv().is_err());
    }

    #[test]
    fn every_request_names_box_and_the_version_in_the_payload() {
        let service = Service::start(Duration::ZERO);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        append(&path);
        let journal = Journal::start(&path).unwrap();
        let mut session = service.session(LaunchOutcome::Unknown, Duration::from_secs(1));
        session.observe(journal, catalog());
        append_start(&path);
        append_control(&path, "box_stopped", "ok", None);
        session.finish(Instant::now(), ExitOutcome::Zero);
        let events: Vec<Value> = (0..3).map(|_| service.event()).collect();
        let mut names: Vec<_> = events
            .iter()
            .map(|e| e["event"].as_str().unwrap())
            .collect();
        names.sort_unstable();
        assert_eq!(names, ["polling/1", "run/1", "shutdown/1"]);
        let version = events[0]["context"]["box_version"].as_str().unwrap();
        assert_eq!(version, "1.2.3");
        let agents: Vec<String> = service.user_agents.try_iter().collect();
        assert!(!agents.is_empty());
        for agent in agents {
            assert_eq!(agent, format!("box/{version}"));
        }
    }

    #[test]
    fn delivery_sends_preparation_failure_and_nonzero_shutdown() {
        let service = Service::start(Duration::ZERO);
        let session = service.session(
            LaunchOutcome::PreparationFailed(FailureReason::ProfileMissing),
            Duration::from_secs(1),
        );
        let completed = session.started + Duration::from_millis(321);
        session.finish(completed, ExitOutcome::Nonzero);
        let mut received = [service.event(), service.event()];
        received.sort_by_key(|event| event["event"].as_str().unwrap().to_owned());
        let [run, shutdown] = received;
        assert_eq!(run["event"], "run/1");
        assert_eq!(
            run["data"],
            json!({"box_launched":false,"failure_reason":"profile_missing","startup_latency_ms":null})
        );
        assert_eq!(shutdown["event"], "shutdown/1");
        assert_eq!(shutdown["data"]["exit_outcome"], "nonzero");
        assert_eq!(shutdown["data"]["invocation_duration_ms"], 321);
        for key in ["installation_id", "run_id", "context"] {
            assert_eq!(run[key], shutdown[key], "{key}");
        }
        assert!(service.events.try_recv().is_err());
    }
}
