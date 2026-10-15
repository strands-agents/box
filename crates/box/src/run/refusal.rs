//! Kernel refusals the box observed, rate-limited into telemetry.
//!
//! A workload chooses how often it is refused, so the box records the first refusal under each
//! key at once, counts repeats, and caps how many keys it tracks. Past the cap a new key is counted
//! under its syscall alone, so arguments a workload picks cannot hide a later kind of call. Every
//! notification is still answered: the limit drops records, never responses.

// Only the Linux watcher feeds the recorder today; macOS joins with Seatbelt violation reports.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::run::telemetry::Collector;

/// What one refusal is grouped under.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct RefusalKey {
    pub(crate) executable: String,
    pub(crate) syscall: String,
    pub(crate) arguments: Option<String>,
}

/// What the limiter decided for one refusal.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admit {
    /// Emit a record standing for this call and `suppressed` earlier ones.
    Record { suppressed: u64 },
    /// The first refusal past the key cap: emit the one overflow notice, and a record for this call.
    FirstOverflow,
    /// Counted, not emitted.
    Nothing,
}

/// What remains to emit when the box stops.
#[derive(Debug, Default)]
pub(crate) struct Drained {
    /// Each key's count since its last record, in key order, zero counts left out.
    pub(crate) pending: Vec<(RefusalKey, u64)>,
    /// Refusals under keys past the cap.
    pub(crate) overflow: u64,
}

/// Syscall numbers below this are each their own bucket past the cap; every arch Box supports
/// numbers its calls below it.
const NUMBERED: u32 = 1024;

/// What a refusal past the key cap is counted under: its syscall, with every number at or past
/// [`NUMBERED`] in one bucket, so the workload cannot grow the set by calling made-up numbers.
fn syscall_bucket(syscall: &str) -> String {
    match syscall
        .strip_prefix("syscall_")
        .and_then(|number| number.parse::<u32>().ok())
    {
        Some(number) if number >= NUMBERED => "syscall_out_of_range".to_string(),
        _ => syscall.to_string(),
    }
}

#[derive(Debug)]
struct Window {
    opened: Instant,
    count: u64,
}

impl Window {
    fn opened(now: Instant) -> Self {
        Self {
            opened: now,
            count: 0,
        }
    }
}

/// One box's refusal limiter, shared by every launch in it.
#[derive(Debug)]
pub(crate) struct RefusalLimiter {
    window: Duration,
    cap: usize,
    keys: HashMap<RefusalKey, Window>,
    /// Past the cap: one window per syscall bucket, bounded by the buckets there are.
    by_syscall: HashMap<RefusalKey, Window>,
    overflow: u64,
}

impl RefusalLimiter {
    /// How long repeats under one key are only counted.
    pub(crate) const WINDOW: Duration = Duration::from_secs(10);
    /// How many distinct keys one box tracks.
    pub(crate) const CAP: usize = 256;

    pub(crate) fn new(window: Duration, cap: usize) -> Self {
        Self {
            window,
            cap,
            keys: HashMap::new(),
            by_syscall: HashMap::new(),
            overflow: 0,
        }
    }

    pub(crate) fn admit(&mut self, key: &RefusalKey, now: Instant) -> Admit {
        if let Some(admit) = Self::repeat(&mut self.keys, key, now, self.window) {
            return admit;
        }
        if self.keys.len() < self.cap {
            self.keys.insert(key.clone(), Window::opened(now));
            return Admit::Record { suppressed: 0 };
        }
        self.overflow += 1;
        let coarse = RefusalKey {
            executable: String::new(),
            syscall: syscall_bucket(&key.syscall),
            arguments: None,
        };
        if let Some(admit) = Self::repeat(&mut self.by_syscall, &coarse, now, self.window) {
            return admit;
        }
        self.by_syscall.insert(coarse, Window::opened(now));
        if self.overflow == 1 {
            Admit::FirstOverflow
        } else {
            Admit::Record { suppressed: 0 }
        }
    }

    /// The decision for a key already tracked in `windows`, or `None` for a new one.
    fn repeat(
        windows: &mut HashMap<RefusalKey, Window>,
        key: &RefusalKey,
        now: Instant,
        length: Duration,
    ) -> Option<Admit> {
        let window = windows.get_mut(key)?;
        if now.saturating_duration_since(window.opened) < length {
            window.count += 1;
            return Some(Admit::Nothing);
        }
        let suppressed = window.count;
        *window = Window::opened(now);
        Some(Admit::Record { suppressed })
    }

    pub(crate) fn drain(&mut self) -> Drained {
        let mut pending: Vec<(RefusalKey, u64)> = self
            .keys
            .iter_mut()
            .chain(self.by_syscall.iter_mut())
            .filter(|(_, window)| window.count > 0)
            .map(|(key, window)| (key.clone(), std::mem::take(&mut window.count)))
            .collect();
        pending.sort();
        Drained {
            pending,
            overflow: std::mem::take(&mut self.overflow),
        }
    }
}

/// One refusal the watcher read, with its caller's details.
#[derive(Debug, Clone)]
pub(crate) struct Observed {
    pub(crate) pid: u32,
    pub(crate) executable: String,
    pub(crate) argv: Vec<String>,
    pub(crate) syscall: String,
    pub(crate) arguments: Option<String>,
}

/// Test-only view of what reached the collector.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct Emitted {
    pub(crate) syscall: String,
    pub(crate) suppressed: u64,
}

/// The box's one sink for kernel refusals, shared by every launch in it.
pub(crate) struct RefusalRecorder {
    collector: Option<Arc<Collector>>,
    limiter: Mutex<RefusalLimiter>,
    #[cfg(test)]
    recorded: Mutex<Vec<Emitted>>,
    /// Test-only: each control record's subject, reason, and detail.
    #[cfg(test)]
    controls: Mutex<Vec<(String, String, Option<String>)>>,
}

impl RefusalRecorder {
    pub(crate) fn over(collector: Arc<Collector>) -> Arc<Self> {
        Arc::new(Self {
            collector: Some(collector),
            limiter: Mutex::new(RefusalLimiter::new(
                RefusalLimiter::WINDOW,
                RefusalLimiter::CAP,
            )),
            #[cfg(test)]
            recorded: Mutex::new(Vec::new()),
            #[cfg(test)]
            controls: Mutex::new(Vec::new()),
        })
    }

    #[cfg(test)]
    pub(crate) fn discarding() -> Arc<Self> {
        Self::discarding_with_cap(RefusalLimiter::CAP)
    }

    #[cfg(test)]
    pub(crate) fn discarding_with_cap(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            collector: None,
            limiter: Mutex::new(RefusalLimiter::new(RefusalLimiter::WINDOW, cap)),
            recorded: Mutex::new(Vec::new()),
            controls: Mutex::new(Vec::new()),
        })
    }

    #[cfg(test)]
    pub(crate) fn controls(&self) -> Vec<(String, String, Option<String>)> {
        self.controls.lock().map(|c| c.clone()).unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn recorded(&self) -> Vec<Emitted> {
        self.recorded.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// Count one refusal, and emit it if the limiter says so.
    pub(crate) fn observe(&self, refusal: Observed) {
        let key = RefusalKey {
            executable: refusal.executable.clone(),
            syscall: refusal.syscall.clone(),
            arguments: refusal.arguments.clone(),
        };
        let admitted = match self.limiter.lock() {
            Ok(mut limiter) => limiter.admit(&key, std::time::Instant::now()),
            Err(_) => return,
        };
        match admitted {
            Admit::Record { suppressed } => self.emit(&refusal, suppressed),
            Admit::FirstOverflow => {
                self.control("box", "rate_cap", None);
                self.emit(&refusal, 0);
            }
            Admit::Nothing => {}
        }
    }

    /// One launch's install fell back, so its refusals are not observed.
    pub(crate) fn unobserved(&self, launch: &str, errno: i32) {
        self.control(launch, &errno_name(errno), None);
    }

    /// Emit every pending count and the overflow tally. Called on drop, and safe to call twice.
    pub(crate) fn flush(&self) {
        let drained = match self.limiter.lock() {
            Ok(mut limiter) => limiter.drain(),
            Err(_) => return,
        };
        for (key, count) in drained.pending {
            let refusal = Observed {
                pid: 0,
                executable: key.executable,
                argv: Vec::new(),
                syscall: key.syscall,
                arguments: key.arguments,
            };
            self.emit(&refusal, count - 1);
        }
        if drained.overflow > 0 {
            self.control(
                "box",
                "rate_cap",
                Some(format!("{} refusals", drained.overflow)),
            );
        }
    }

    fn emit(&self, refusal: &Observed, suppressed: u64) {
        #[cfg(test)]
        if let Ok(mut recorded) = self.recorded.lock() {
            recorded.push(Emitted {
                syscall: refusal.syscall.clone(),
                suppressed,
            });
        }
        if let Some(collector) = &self.collector {
            let args: Vec<String> = refusal.argv.iter().skip(1).cloned().collect();
            let process = telemetry::Subject::process(&refusal.executable, &args, &[], "");
            collector.refusal(
                telemetry::RefusalRecord::seccomp(
                    &refusal.syscall,
                    refusal.arguments.as_deref(),
                    refusal.pid,
                    process,
                )
                .suppressed(suppressed),
            );
        }
    }

    /// One `refusals_unobserved` control record.
    fn control(&self, subject: &str, reason: &str, detail: Option<String>) {
        #[cfg(test)]
        if let Ok(mut controls) = self.controls.lock() {
            controls.push((subject.to_string(), reason.to_string(), detail.clone()));
        }
        if let Some(collector) = &self.collector {
            let record = telemetry::ControlRecord::refused(
                telemetry::ControlOperation::RefusalsUnobserved,
                subject,
                reason,
            );
            collector.control(match &detail {
                Some(detail) => record.detailed(detail),
                None => record,
            });
        }
    }
}

impl Drop for RefusalRecorder {
    /// The last launch is gone, so what the limiter still counts is emitted before the collector
    /// drains.
    fn drop(&mut self) {
        self.flush();
    }
}

/// The errno name for a fallback's control record. Mirrors containment's own list.
fn errno_name(errno: i32) -> String {
    match errno {
        libc::EBUSY => "EBUSY".into(),
        libc::EINVAL => "EINVAL".into(),
        libc::ENOSYS => "ENOSYS".into(),
        libc::EACCES => "EACCES".into(),
        libc::EFAULT => "EFAULT".into(),
        libc::ENOMEM => "ENOMEM".into(),
        libc::EPERM => "EPERM".into(),
        other => format!("errno_{other}"),
    }
}

/// One refusal as the watcher records it. The syscall and its arguments come from the kernel and
/// are always kept; the caller's `/proc` details are dropped when the id went stale while they were
/// read, since the pid may name another process by then.
fn observed_from(
    still_valid: bool,
    pid: u32,
    exe: &[u8],
    cmdline: &[u8],
    syscall: String,
    arguments: Option<String>,
) -> Observed {
    let (executable, argv) = if still_valid {
        process_details_from(exe, cmdline)
    } else {
        (String::new(), Vec::new())
    };
    Observed {
        pid,
        executable,
        argv,
        syscall,
        arguments,
    }
}

/// A caller's executable and argv from the raw bytes of its `/proc` entries, lossy and bounded.
fn process_details_from(exe: &[u8], cmdline: &[u8]) -> (String, Vec<String>) {
    let executable = String::from_utf8_lossy(exe)
        .trim_end_matches('\0')
        .to_string();
    let argv = cmdline
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .take(65)
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    (executable, argv)
}

/// One launch's watcher thread. Dropping it stops the thread within about a second.
#[cfg(target_os = "linux")]
pub(crate) struct RefusalWatch {
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl Drop for RefusalWatch {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(target_os = "linux")]
impl RefusalRecorder {
    /// Read `launch`'s handoff from `control`, then answer its refusals until it ends.
    pub(crate) fn watch(
        self: &Arc<Self>,
        control: std::os::unix::net::UnixStream,
        launch: String,
    ) -> RefusalWatch {
        use containment::refusal::{Handoff, Next, describe, receive_handoff};
        use std::sync::atomic::Ordering;

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let recorder = Arc::clone(self);
        let stopping = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("strands-box-refusals".to_string())
            .spawn(move || {
                let _ = control.set_read_timeout(Some(std::time::Duration::from_secs(1)));
                let handoff = loop {
                    if stopping.load(Ordering::SeqCst) {
                        return;
                    }
                    match receive_handoff(&control) {
                        Ok(handoff) => break handoff,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock
                                    | std::io::ErrorKind::TimedOut
                                    | std::io::ErrorKind::Interrupted
                            ) =>
                        {
                            continue;
                        }
                        Err(_) => return,
                    }
                };
                let listener = match handoff {
                    Handoff::Observed(listener) => listener,
                    Handoff::Unobserved { errno } => return recorder.unobserved(&launch, errno),
                    Handoff::Absent => return,
                };
                while !stopping.load(Ordering::SeqCst) {
                    match listener.next(std::time::Duration::from_millis(200)) {
                        Ok(Next::Notification(notification)) => {
                            let exe = std::fs::read_link(format!("/proc/{}/exe", notification.pid))
                                .map(|path| path.into_os_string().into_encoded_bytes())
                                .unwrap_or_default();
                            let cmdline =
                                std::fs::read(format!("/proc/{}/cmdline", notification.pid))
                                    .unwrap_or_default();
                            let valid = listener.still_valid(notification.id);
                            // Answered before anything else can fail: the workload is waiting.
                            let _ = listener.refuse(notification.id);
                            let description = describe(notification.syscall, &notification.args);
                            recorder.observe(observed_from(
                                valid,
                                notification.pid,
                                &exe,
                                &cmdline,
                                description.syscall,
                                description.arguments,
                            ));
                        }
                        Ok(Next::Idle) => {}
                        Ok(Next::Ended) | Err(_) => return,
                    }
                }
            })
            .ok();
        RefusalWatch { stop, thread }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn key(syscall: &str) -> RefusalKey {
        RefusalKey {
            executable: "/bin/x".into(),
            syscall: syscall.into(),
            arguments: None,
        }
    }

    #[test]
    fn the_first_refusal_under_a_key_is_recorded_at_once() {
        let mut limiter = RefusalLimiter::new(Duration::from_secs(10), 256);
        assert_eq!(
            limiter.admit(&key("bpf"), Instant::now()),
            Admit::Record { suppressed: 0 }
        );
    }

    #[test]
    fn repeats_inside_the_window_are_counted_and_carried_by_the_next_record() {
        let mut limiter = RefusalLimiter::new(Duration::from_secs(10), 256);
        let start = Instant::now();
        limiter.admit(&key("bpf"), start);
        for second in 1..=5 {
            assert_eq!(
                limiter.admit(&key("bpf"), start + Duration::from_secs(second)),
                Admit::Nothing
            );
        }
        assert_eq!(
            limiter.admit(&key("bpf"), start + Duration::from_secs(11)),
            Admit::Record { suppressed: 5 }
        );
        assert_eq!(
            limiter.admit(&key("bpf"), start + Duration::from_secs(12)),
            Admit::Nothing
        );
    }

    #[test]
    fn records_and_suppressed_counts_sum_to_every_call() {
        let mut limiter = RefusalLimiter::new(Duration::from_secs(10), 256);
        let start = Instant::now();
        let mut total = 0u64;
        for call in 0..100_000u64 {
            if let Admit::Record { suppressed } =
                limiter.admit(&key("socket"), start + Duration::from_micros(call * 3))
            {
                total += 1 + suppressed;
            }
        }
        for (_, pending) in limiter.drain().pending {
            total += 1 + (pending - 1);
        }
        assert_eq!(total, 100_000);
    }

    fn keyed(syscall: &str, arguments: &str) -> RefusalKey {
        RefusalKey {
            arguments: Some(arguments.into()),
            ..key(syscall)
        }
    }

    #[test]
    fn past_the_cap_new_keys_are_counted_per_syscall() {
        let mut limiter = RefusalLimiter::new(Duration::from_secs(10), 2);
        let now = Instant::now();
        assert_eq!(
            limiter.admit(&key("a"), now),
            Admit::Record { suppressed: 0 }
        );
        assert_eq!(
            limiter.admit(&key("b"), now),
            Admit::Record { suppressed: 0 }
        );
        // The first key past the cap announces it, and is still recorded under its syscall.
        assert_eq!(limiter.admit(&key("c"), now), Admit::FirstOverflow);
        // Another syscall past the cap keeps its own record.
        assert_eq!(
            limiter.admit(&key("d"), now),
            Admit::Record { suppressed: 0 }
        );
        // New arguments to a syscall already counted past the cap are only counted.
        assert_eq!(limiter.admit(&keyed("c", "x=1"), now), Admit::Nothing);
        // A key admitted before the cap keeps working.
        assert_eq!(limiter.admit(&key("a"), now), Admit::Nothing);
        assert_eq!(
            limiter.admit(&keyed("c", "x=2"), now + Duration::from_secs(11)),
            Admit::Record { suppressed: 1 }
        );
        let drained = limiter.drain();
        assert_eq!(drained.overflow, 4);
        assert_eq!(drained.pending, vec![(key("a"), 1)]);
    }

    #[test]
    fn records_and_suppressed_counts_sum_to_every_call_past_the_cap() {
        let mut limiter = RefusalLimiter::new(Duration::from_secs(10), 4);
        let start = Instant::now();
        let mut total = 0u64;
        for call in 0..50_000u64 {
            let refusal = keyed(&format!("s{}", call % 20), &format!("x={}", call % 7));
            match limiter.admit(&refusal, start + Duration::from_millis(call)) {
                Admit::Record { suppressed } => total += 1 + suppressed,
                Admit::FirstOverflow => total += 1,
                Admit::Nothing => {}
            }
        }
        for (_, pending) in limiter.drain().pending {
            total += pending;
        }
        assert_eq!(total, 50_000);
    }

    #[test]
    fn a_numbered_syscall_past_the_known_range_shares_one_bucket() {
        assert_eq!(syscall_bucket("syscall_99999"), "syscall_out_of_range");
        assert_eq!(syscall_bucket("syscall_70000"), "syscall_out_of_range");
        assert_eq!(syscall_bucket("syscall_216"), "syscall_216");
        assert_eq!(syscall_bucket("bpf"), "bpf");
    }

    #[test]
    fn drain_reports_only_nonzero_counts_and_resets_them() {
        let mut limiter = RefusalLimiter::new(Duration::from_secs(10), 256);
        let now = Instant::now();
        limiter.admit(&key("a"), now);
        limiter.admit(&key("b"), now);
        limiter.admit(&key("b"), now);
        assert_eq!(limiter.drain().pending, vec![(key("b"), 1)]);
        assert!(limiter.drain().pending.is_empty());
    }
    fn observed(syscall: &str, pid: u32) -> Observed {
        Observed {
            pid,
            executable: "/usr/bin/python3".into(),
            argv: vec!["python3".into(), "-c".into(), "token=abc".into()],
            syscall: syscall.into(),
            arguments: None,
        }
    }

    #[test]
    fn a_repeat_from_another_pid_is_counted_under_the_same_key() {
        let recorder = RefusalRecorder::discarding();
        recorder.observe(observed("bpf", 1));
        recorder.observe(observed("bpf", 2)); // same exe, same call: counted, not recorded
        let recorded = recorder.recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].syscall, "bpf");
    }

    #[test]
    fn a_fallback_is_announced_with_its_launch_and_errno() {
        let recorder = RefusalRecorder::discarding();
        recorder.unobserved("mcp:files", libc::EBUSY);
        assert_eq!(
            recorder.controls(),
            vec![("mcp:files".to_string(), "EBUSY".to_string(), None)]
        );
    }

    #[test]
    fn the_cap_is_announced_once_and_its_count_flushed_at_stop() {
        let recorder = RefusalRecorder::discarding_with_cap(1);
        recorder.observe(observed("bpf", 1));
        recorder.observe(observed("ptrace", 1));
        recorder.observe(observed("mount", 1));
        recorder.flush();
        let syscalls: Vec<String> = recorder.recorded().into_iter().map(|r| r.syscall).collect();
        assert_eq!(syscalls, vec!["bpf", "ptrace", "mount"]);
        assert_eq!(
            recorder.controls(),
            vec![
                ("box".to_string(), "rate_cap".to_string(), None),
                (
                    "box".to_string(),
                    "rate_cap".to_string(),
                    Some("2 refusals".to_string())
                ),
            ]
        );
    }

    #[test]
    fn a_flood_of_distinct_arguments_does_not_hide_a_later_syscall() {
        let recorder = RefusalRecorder::discarding();
        for pid in 0..300 {
            recorder.observe(Observed {
                arguments: Some(format!("pid={pid} pgid=0")),
                ..observed("setpgid", 1)
            });
        }
        recorder.observe(observed("bpf", 1));
        let recorded = recorder.recorded();
        assert!(recorded.iter().any(|r| r.syscall == "bpf"));
        // 256 keyed records, then one for setpgid past the cap; the rest are counted.
        assert_eq!(
            recorded.iter().filter(|r| r.syscall == "setpgid").count(),
            257
        );
        assert_eq!(recorder.controls().len(), 1);
    }

    #[test]
    fn flush_emits_each_pending_count_as_one_record() {
        let recorder = RefusalRecorder::discarding();
        for pid in 0..10 {
            recorder.observe(observed("bpf", pid));
        }
        recorder.flush();
        let suppressed: Vec<u64> = recorder.recorded().iter().map(|r| r.suppressed).collect();
        assert_eq!(suppressed, vec![0, 8]); // 1 + 0, then 1 + 8: ten calls
    }

    #[test]
    fn a_stale_notification_is_recorded_without_its_process() {
        // The syscall and its arguments come from the kernel; only what `/proc` said may belong to
        // another process by now. A workload that interrupts its own refused call is still seen.
        let refusal = observed_from(
            false,
            7,
            b"/usr/bin/other",
            b"other\0--flag\0",
            "bpf".into(),
            None,
        );
        assert_eq!(refusal.syscall, "bpf");
        assert_eq!(refusal.pid, 7);
        assert!(refusal.executable.is_empty());
        assert!(refusal.argv.is_empty());
        let recorder = RefusalRecorder::discarding();
        recorder.observe(refusal);
        assert_eq!(recorder.recorded().len(), 1);

        let valid = observed_from(true, 7, b"/bin/x", b"x\0-v\0", "bpf".into(), None);
        assert_eq!(valid.executable, "/bin/x");
        assert_eq!(valid.argv, vec!["x".to_string(), "-v".to_string()]);
    }

    #[test]
    fn process_details_tolerate_garbage() {
        let (exe, argv) = process_details_from(b"\xff\xfe/bin/\x00", &[0xff, b'a', 0, b'b', 0]);
        assert!(exe.contains('\u{fffd}'));
        assert_eq!(argv.len(), 2);
        let long = vec![b'x'; 1 << 20];
        let (_, argv) = process_details_from(b"/bin/x", &long);
        assert_eq!(argv.len(), 1); // one argument; `Subject` bounds its length
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dropping_a_watch_joins_within_two_seconds() {
        let recorder = RefusalRecorder::discarding();
        let (box_side, _silent) = std::os::unix::net::UnixStream::pair().expect("pair");
        let watch = recorder.watch(box_side, "test".to_string());
        let (done, joined) = std::sync::mpsc::channel();
        // Dropped on its own thread, so a watch that never stops fails the test instead of hanging it.
        std::thread::spawn(move || {
            drop(watch);
            let _ = done.send(());
        });
        assert!(joined.recv_timeout(Duration::from_secs(2)).is_ok());
    }
}
