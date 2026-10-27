//! Linux filesystem monitoring for selected workloads.
mod broker;
mod fault;
mod guard;
pub(crate) use guard::Guard as EntryGuard;
mod notify;
mod probe;

static PATH_HANDLES: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::error::{BoxError, SuperviseError};
use crate::run::telemetry::DecisionRecorder;
use policy::{GovernedBox, PathResolver, PolicyEngine};

const REQUEST_DEADLINE: Duration = Duration::from_secs(5);
const STOP_WAIT: Duration = Duration::from_secs(1);
const WATCH_INTERVAL: Duration = Duration::from_millis(25);

fn failure(reason: impl ToString) -> BoxError {
    SuperviseError::Control {
        reason: reason.to_string(),
    }
    .into()
}
struct Worker {
    task: JoinHandle<()>,
    busy: Arc<Mutex<Option<Instant>>>,
}
struct State {
    guard: Arc<guard::Guard>,
    engine: Arc<PolicyEngine>,
    recorder: Arc<DecisionRecorder>,
    resolver: PathResolver,
    governed: GovernedBox,
    stopped: AtomicBool,
    fatal_reason: OnceLock<String>,
    workers: Mutex<Vec<Worker>>,
    fatal: tokio::sync::mpsc::UnboundedSender<BoxError>,
}
impl State {
    fn fail(&self, reason: impl ToString) {
        // Workload exit can win the supervisor's select before it reads this channel.
        // Keep the first error until stop has joined the worker that reported it.
        let reason = self.fatal_reason.get_or_init(|| reason.to_string());
        self.stopped.store(true, Ordering::Release);
        let _ = self.fatal.send(failure(reason));
    }
}
#[derive(Clone)]
pub(crate) struct Registration(Arc<State>);
pub(crate) struct FileMonitor {
    registration: Registration,
    watchdog: Option<JoinHandle<()>>,
}
struct ActiveRequest(Arc<Mutex<Option<Instant>>>);
impl ActiveRequest {
    fn begin(busy: Arc<Mutex<Option<Instant>>>) -> io::Result<Self> {
        *busy
            .lock()
            .map_err(|error| io::Error::other(error.to_string()))? = Some(Instant::now());
        Ok(Self(busy))
    }
}
impl Drop for ActiveRequest {
    fn drop(&mut self) {
        if let Ok(mut busy) = self.0.lock() {
            *busy = None;
        }
    }
}
impl FileMonitor {
    pub(crate) fn start(
        engine: Arc<PolicyEngine>,
        recorder: Arc<DecisionRecorder>,
        name: &str,
        home: &Path,
        fatal: tokio::sync::mpsc::UnboundedSender<BoxError>,
        guard: Option<Arc<EntryGuard>>,
    ) -> Result<Self, BoxError> {
        let guard = guard.ok_or_else(|| {
            failure("native entry guard was not loaded; start Box with CAP_BPF and CAP_PERFMON")
        })?;
        let state = Arc::new(State {
            guard,
            engine,
            recorder,
            resolver: PathResolver::over([PathBuf::from("/")])
                .map_err(failure)?
                .reporting_under(home),
            governed: GovernedBox::assigned(name),
            stopped: AtomicBool::new(false),
            fatal_reason: OnceLock::new(),
            workers: Mutex::new(Vec::new()),
            fatal,
        });
        let weak = Arc::downgrade(&state);
        let watchdog = std::thread::Builder::new()
            .name("linux-native-deadline".into())
            .spawn(move || {
                while let Some(state) = weak.upgrade() {
                    if state.stopped.load(Ordering::Acquire) {
                        break;
                    }
                    let expired = state
                        .workers
                        .lock()
                        .map(|workers| {
                            workers.iter().any(|worker| {
                                worker
                                    .busy
                                    .lock()
                                    .map(|busy| {
                                        busy.is_some_and(|started| {
                                            started.elapsed() >= REQUEST_DEADLINE
                                        })
                                    })
                                    .unwrap_or(true)
                            })
                        })
                        .unwrap_or(true);
                    if expired {
                        state.fail("native request deadline exceeded");
                        break;
                    }
                    drop(state);
                    std::thread::sleep(WATCH_INTERVAL);
                }
            })
            .map_err(failure)?;
        Ok(Self {
            registration: Registration(state),
            watchdog: Some(watchdog),
        })
    }
    pub(crate) fn registration(&self) -> Registration {
        self.registration.clone()
    }
    pub(crate) fn stop(&mut self) -> Result<(), BoxError> {
        self.registration.0.stopped.store(true, Ordering::Release);
        let workers = std::mem::take(&mut *self.registration.0.workers.lock().map_err(failure)?);
        let deadline = Instant::now() + STOP_WAIT;
        let mut incomplete = false;
        for worker in workers {
            while !worker.task.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            if worker.task.is_finished() {
                if worker.task.join().is_err() {
                    incomplete = true;
                }
            } else {
                incomplete = true;
            }
        }
        if let Some(watchdog) = self.watchdog.take()
            && watchdog.join().is_err()
        {
            incomplete = true;
        }
        if let Some(reason) = self.registration.0.fatal_reason.get() {
            return Err(failure(reason));
        }
        if incomplete {
            return Err(failure(
                "native worker did not stop within the shutdown bound",
            ));
        }
        Ok(())
    }
}
impl Drop for FileMonitor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
impl Registration {
    pub(crate) fn register(&self, mut control: std::os::unix::net::UnixStream) -> io::Result<()> {
        control.set_read_timeout(Some(REQUEST_DEADLINE))?;
        control.set_write_timeout(Some(REQUEST_DEADLINE))?;
        fault::at("registration")?;
        if self.0.stopped.load(Ordering::Acquire) {
            return Err(io::Error::other("native monitor stopped"));
        }
        let mut header = [0_u8; 8];
        control.read_exact(&mut header)?;
        if header != *b"BOXFS\0\x01\0" {
            return Err(io::Error::other(
                "unsupported native filesystem handoff version",
            ));
        }
        let handles = notify::receive_handles(&control, 2)?;
        let mut closed = [0_u8; 1];
        control.read_exact(&mut closed)?;
        notify::validate_registration(&header, &handles, closed[0])?;
        let state = Arc::clone(&self.0);
        let busy = Arc::new(Mutex::new(None));
        let active = Arc::clone(&busy);
        let (ready, registered) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("linux-native-policy".into())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || -> Result<(), Box<dyn std::error::Error>> {
                        notify::checked(unsafe { libc::unshare(libc::CLONE_FS) })?;
                        fault::at("worker-registration")?;
                        let guard = state.guard.register()?;
                        ready.send(())?;
                        let listener = handles[0].as_raw_fd();
                        let root = handles[1].as_raw_fd();
                        while !state.stopped.load(Ordering::Acquire) {
                            let request = match notify::receive(listener) {
                                Ok(request) => request,
                                Err(error) if error.kind() == io::ErrorKind::TimedOut => continue,
                                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => break,
                                Err(error) => return Err(error.into()),
                            };
                            let _active = ActiveRequest::begin(Arc::clone(&active))?;
                            if state.stopped.load(Ordering::Acquire) {
                                break;
                            }
                            let response = if (request.data.number == libc::SYS_openat as i32
                                && (request.data.args[2] & libc::O_CREAT as u64 == 0
                                    || request.data.args[2] & libc::O_PATH as u64 != 0))
                                || request.data.number == libc::SYS_truncate as i32
                            {
                                broker::file_request(
                                    &state.resolver,
                                    &state.engine,
                                    root,
                                    listener,
                                    &request,
                                    &state.governed,
                                    &state.recorder,
                                )
                            } else {
                                broker::entry_request(
                                    &guard,
                                    &state.resolver,
                                    &state.engine,
                                    root,
                                    listener,
                                    &request,
                                    &state.governed,
                                    &state.recorder,
                                )
                            };
                            match response {
                                Ok(response) => {
                                    #[cfg(feature = "test-support")]
                                    eprintln!("NATIVE_RESEARCH_EVENT={response}");
                                    #[cfg(not(feature = "test-support"))]
                                    let _ = response;
                                }
                                Err(error)
                                    if error.downcast_ref::<io::Error>().is_some_and(|error| {
                                        matches!(
                                            error.raw_os_error(),
                                            Some(libc::ENOENT | libc::ESRCH)
                                        )
                                    }) && notify::valid(listener, request.id).is_err_and(
                                        |error| error.raw_os_error() == Some(libc::ENOENT),
                                    ) =>
                                {
                                    #[cfg(feature = "test-support")]
                                    eprintln!(
                                        "NATIVE_RESEARCH_EVENT={{\"outcome\":\"cancelled\"}}"
                                    );
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        Ok(())
                    },
                ));
                let reason = match outcome {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(error.to_string()),
                    Err(_) => Some("native worker panicked".to_string()),
                };
                if let Some(reason) = reason {
                    state.fail(reason);
                }
            })?;
        let mut workers = self
            .0
            .workers
            .lock()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut index = 0;
        while index < workers.len() {
            if workers[index].task.is_finished() {
                let completed = workers.swap_remove(index);
                completed
                    .task
                    .join()
                    .map_err(|_| io::Error::other("native worker panicked"))?;
            } else {
                index += 1;
            }
        }
        workers.push(Worker { task: worker, busy });
        drop(workers);
        registered.recv_timeout(REQUEST_DEADLINE).map_err(|error| {
            self.0.stopped.store(true, Ordering::Release);
            io::Error::other(format!("native worker registration failed: {error}"))
        })?;
        if self.0.stopped.load(Ordering::Acquire) {
            return Err(io::Error::other("native monitor stopped"));
        }
        control.write_all(&[1])
    }
}
pub(crate) fn selected(record: &crate::record::config::Record) -> bool {
    record
        .agent
        .iter()
        .chain(record.tool.values())
        .chain(record.contained_mcp.values().map(|server| &server.spec))
        .any(|spec| {
            spec.native_filesystem_policy
                .unwrap_or(record.experimental_features.native_filesystem_policy)
        })
}

pub(crate) fn preflight() -> Result<(), BoxError> {
    let mut sizes = [0_u16; 3];
    notify::checked(unsafe { libc::syscall(libc::SYS_seccomp, 3, 0, sizes.as_mut_ptr()) as i32 })
        .map_err(failure)?;
    if sizes != [80, 24, 64] {
        return Err(failure("unsupported Linux notification structure sizes"));
    }
    if PATH_HANDLES.get().is_none() {
        let supported = probe::path_handles().map_err(failure)?;
        let _ = PATH_HANDLES.set(supported);
        if !supported {
            eprintln!(
                "strands-box: native filesystem policy: this kernel cannot transfer O_PATH handles; path-only opens are refused"
            );
        }
    }
    Ok(())
}

#[cfg(all(test, box_native_kernel_tests))]
mod mechanism_tests;
