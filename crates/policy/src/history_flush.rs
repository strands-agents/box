//! An owned timer that persists the existing policy engine's history.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::{PolicyEngine, PolicyError};

/// Completed flush calls, including the final call after an explicit shutdown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoryFlushSnapshot {
    /// Completed calls, including failures.
    pub attempts: u64,
    /// Calls that returned success.
    pub successes: u64,
    /// Calls that returned an error or panicked.
    pub failures: u64,
    /// The most recent error, retained after a later successful retry.
    pub last_error: Option<String>,
    /// Total elapsed microseconds, including lock waits.
    pub total_micros: u64,
    /// Longest completed call, including lock waits.
    pub max_micros: u64,
}

/// Owns one flush worker and keeps the policy engine alive until shutdown completes.
#[must_use = "keep the guard alive while events can arrive"]
pub struct HistoryFlusher {
    worker: Worker,
    engine: Arc<PolicyEngine>,
    closed: bool,
}

impl HistoryFlusher {
    pub(crate) fn start(
        engine: Arc<PolicyEngine>,
        interval: Duration,
    ) -> Result<Self, PolicyError> {
        let weak = Arc::downgrade(&engine);
        let flush: Arc<Flush> = Arc::new(move || {
            let engine = weak
                .upgrade()
                .ok_or_else(|| "policy engine was dropped".to_string())?;
            engine.flush_history().map_err(|error| error.to_string())
        });
        Ok(Self {
            worker: Worker::start(interval, flush).map_err(PolicyError::Evaluation)?,
            engine,
            closed: false,
        })
    }

    /// Read completed-call counters without taking the policy engine lock.
    pub fn snapshot(&self) -> HistoryFlushSnapshot {
        snapshot(&self.worker.stats)
    }

    /// Stop and join the worker, then flush once; callers must stop event producers first.
    pub fn shutdown(mut self) -> Result<HistoryFlushSnapshot, PolicyError> {
        self.finish(true)
    }

    fn finish(&mut self, final_flush: bool) -> Result<HistoryFlushSnapshot, PolicyError> {
        if self.closed {
            return Ok(self.snapshot());
        }
        self.worker.finish(final_flush);
        self.closed = true;
        self.engine.release_history_flusher();
        let state = self.snapshot();
        match &state.last_error {
            Some(error) => Err(PolicyError::Evaluation(format!(
                "history flush failed {} time(s): {error}",
                state.failures
            ))),
            None => Ok(state),
        }
    }
}

impl Drop for HistoryFlusher {
    fn drop(&mut self) {
        if let Err(error) = self.finish(!thread::panicking()) {
            eprintln!("policy: history flush shutdown failed: {error}");
        }
    }
}

type Flush = dyn Fn() -> Result<(), String> + Send + Sync + 'static;

struct Worker {
    stop: Option<mpsc::Sender<()>>,
    join: Option<JoinHandle<()>>,
    flush: Arc<Flush>,
    stats: Arc<Mutex<HistoryFlushSnapshot>>,
}

impl Worker {
    fn start(interval: Duration, flush: Arc<Flush>) -> Result<Self, String> {
        if interval.is_zero() {
            return Err("history flush interval must be positive".to_string());
        }
        let (stop, receive) = mpsc::channel();
        let stats = Arc::new(Mutex::new(HistoryFlushSnapshot::default()));
        let worker_flush = Arc::clone(&flush);
        let worker_stats = Arc::clone(&stats);
        let join = thread::Builder::new()
            .name("box-history-flush".to_string())
            .spawn(move || {
                while let Err(mpsc::RecvTimeoutError::Timeout) = receive.recv_timeout(interval) {
                    if !perform(&worker_flush, &worker_stats) {
                        break;
                    }
                }
            })
            .map_err(|error| format!("start history flush worker: {error}"))?;
        Ok(Self {
            stop: Some(stop),
            join: Some(join),
            flush,
            stats,
        })
    }

    fn finish(&mut self, final_flush: bool) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let Some(join) = self.join.take() else { return };
        if join.join().is_err() {
            record(
                &self.stats,
                Duration::ZERO,
                Err("history flush worker panicked outside its callback".to_string()),
            );
        }
        if final_flush {
            perform(&self.flush, &self.stats);
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.finish(false);
    }
}

fn snapshot(stats: &Mutex<HistoryFlushSnapshot>) -> HistoryFlushSnapshot {
    match stats.lock() {
        Ok(stats) => stats.clone(),
        Err(_) => HistoryFlushSnapshot {
            failures: 1,
            last_error: Some("history flush counters lock poisoned".to_string()),
            ..HistoryFlushSnapshot::default()
        },
    }
}

fn perform(flush: &Arc<Flush>, stats: &Mutex<HistoryFlushSnapshot>) -> bool {
    let started = Instant::now();
    let outcome = catch_unwind(AssertUnwindSafe(|| flush()));
    let panicked = outcome.is_err();
    let outcome = outcome.unwrap_or_else(|_| Err("history flush callback panicked".to_string()));
    record(stats, started.elapsed(), outcome);
    !panicked
}

fn record(stats: &Mutex<HistoryFlushSnapshot>, elapsed: Duration, outcome: Result<(), String>) {
    let Ok(mut stats) = stats.lock() else {
        eprintln!("policy: history flush counters lock poisoned");
        return;
    };
    stats.attempts = stats.attempts.saturating_add(1);
    let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
    stats.total_micros = stats.total_micros.saturating_add(micros);
    stats.max_micros = stats.max_micros.max(micros);
    match outcome {
        Ok(()) => stats.successes = stats.successes.saturating_add(1),
        Err(error) => {
            stats.failures = stats.failures.saturating_add(1);
            eprintln!("policy: periodic history flush failed: {error}");
            stats.last_error = Some(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn a_timer_calls_flush_without_event_submissions() {
        let (sent, received) = mpsc::channel();
        let flush: Arc<Flush> = Arc::new(move || {
            sent.send(()).expect("receiver remains alive");
            Ok(())
        });
        let mut worker = Worker::start(Duration::from_millis(10), flush).expect("starts");
        received
            .recv_timeout(Duration::from_secs(2))
            .expect("timer runs while idle");
        worker.finish(true);
        let state = snapshot(&worker.stats);
        assert!(state.successes >= 2, "timer and final flush both completed");
        assert_eq!(state.failures, 0);
        assert!(worker.join.is_none());
    }

    #[test]
    fn shutdown_wakes_a_long_sleep_and_flushes_once() {
        let calls = Arc::new(AtomicU64::new(0));
        let worker_calls = Arc::clone(&calls);
        let mut worker = Worker::start(
            Duration::from_secs(3600),
            Arc::new(move || {
                worker_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        )
        .expect("starts");
        let started = Instant::now();
        worker.finish(true);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "shutdown does not wait for the timer interval"
        );
        worker.finish(true);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "shutdown is idempotent");
    }

    #[test]
    fn a_failed_flush_is_reported_and_retried() {
        let calls = Arc::new(AtomicU64::new(0));
        let worker_calls = Arc::clone(&calls);
        let (sent, received) = mpsc::channel();
        let mut worker = Worker::start(
            Duration::from_millis(10),
            Arc::new(move || {
                let call = worker_calls.fetch_add(1, Ordering::SeqCst);
                sent.send(call).expect("receiver remains alive");
                if call == 0 {
                    Err("injected storage error".to_string())
                } else {
                    Ok(())
                }
            }),
        )
        .expect("starts");
        assert_eq!(
            received
                .recv_timeout(Duration::from_secs(2))
                .expect("first attempt"),
            0
        );
        assert_eq!(
            received
                .recv_timeout(Duration::from_secs(2))
                .expect("retry"),
            1
        );
        worker.finish(true);
        let state = snapshot(&worker.stats);
        assert_eq!(state.failures, 1);
        assert!(state.successes >= 2);
        assert_eq!(state.last_error.as_deref(), Some("injected storage error"));
    }

    #[test]
    fn a_panicking_flush_stops_the_timer_and_remains_observable() {
        let (sent, received) = mpsc::channel();
        let mut worker = Worker::start(
            Duration::from_millis(10),
            Arc::new(move || {
                sent.send(()).expect("receiver remains alive");
                panic!("injected flush panic");
            }),
        )
        .expect("starts");
        received
            .recv_timeout(Duration::from_secs(2))
            .expect("callback starts");
        worker.finish(false);
        let state = snapshot(&worker.stats);
        assert_eq!(state.attempts, 1);
        assert_eq!(state.failures, 1);
        assert_eq!(
            state.last_error.as_deref(),
            Some("history flush callback panicked")
        );
    }

    #[test]
    fn shutdown_returns_a_final_flush_error_and_releases_worker_ownership() {
        let directory = tempfile::tempdir().expect("temporary history directory");
        let engine = Arc::new(
            PolicyEngine::open(Vec::new(), &directory.path().join("history.redb"))
                .expect("history opens"),
        );
        let mut flusher = engine
            .start_history_flusher(Duration::from_secs(3600))
            .expect("worker starts");
        flusher.worker.flush = Arc::new(|| Err("injected final flush error".to_string()));
        let error = flusher
            .shutdown()
            .expect_err("final error reaches the caller");
        assert!(error.to_string().contains("injected final flush error"));
        engine
            .start_history_flusher(Duration::from_secs(3600))
            .expect("failed shutdown released ownership")
            .shutdown()
            .expect("replacement worker shuts down");
    }

    #[test]
    fn a_zero_timer_interval_is_rejected() {
        assert!(Worker::start(Duration::ZERO, Arc::new(|| Ok(()))).is_err());
    }
}
