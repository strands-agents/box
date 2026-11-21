//! The Box owner's storage failure latch and admission boundary.

#[cfg(target_os = "linux")]
mod launcher;
#[cfg(target_os = "linux")]
mod sources;

use std::fmt::Display;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::error::{BoxError, SuperviseError};

/// The shared owner of storage admission for the agent and its local leaves.
#[derive(Clone)]
pub(crate) struct StorageOwner(Arc<State>);

struct State {
    admission: Mutex<Admission>,
    closed: tokio::sync::watch::Sender<bool>,
    fatal: tokio::sync::mpsc::UnboundedSender<BoxError>,
    workers: Mutex<Vec<Worker>>,
    #[cfg(target_os = "linux")]
    hosted: Mutex<Option<Arc<box_shell::StorageView>>>,
    #[cfg(target_os = "linux")]
    launcher: Mutex<Option<launcher::Launcher>>,
    #[cfg(target_os = "linux")]
    sources: Mutex<Option<sources::SourceHelper>>,
}

#[derive(Default)]
struct Admission {
    closed: bool,
    failure: Option<String>,
}

impl StorageOwner {
    pub(super) fn new(fatal: tokio::sync::mpsc::UnboundedSender<BoxError>) -> Self {
        let (closed, _) = tokio::sync::watch::channel(false);
        Self(Arc::new(State {
            admission: Mutex::new(Admission::default()),
            closed,
            fatal,
            workers: Mutex::new(Vec::new()),
            #[cfg(target_os = "linux")]
            hosted: Mutex::new(None),
            #[cfg(target_os = "linux")]
            launcher: Mutex::new(None),
            #[cfg(target_os = "linux")]
            sources: Mutex::new(None),
        }))
    }

    /// Own cleanup until HostedBox has finished every fallible construction step.
    pub(super) fn startup_guard(&self) -> StartupGuard {
        StartupGuard(Some(self.clone()))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn configure_sources(
        &self,
        roots: &[std::path::PathBuf],
        trusted: &crate::run::installation::TrustedInstallation,
    ) -> Result<(), BoxError> {
        if roots.is_empty() {
            return Ok(());
        }
        self.check()?;
        let helper = sources::SourceHelper::start(roots, trusted)?;
        let (control, cancel) = helper.monitor()?;
        self.admit(|| {
            let mut sources = self
                .0
                .sources
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if sources.is_some() {
                return Err(SuperviseError::Control {
                    reason: "Box source helper already configured".into(),
                }
                .into());
            }
            *sources = Some(helper);
            Ok(())
        })?;
        self.spawn_worker(Arc::clone(&cancel), move || {
            let result = containment::storage::sources::monitor(&control);
            if cancel.is_cancelled() {
                return Err(SuperviseError::StorageCancelled.into());
            }
            result.map_err(|error| {
                SuperviseError::Control {
                    reason: error.to_string(),
                }
                .into()
            })
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn subscribe_sources(
        &self,
        roots: &[std::path::PathBuf],
    ) -> Result<std::os::unix::net::UnixStream, BoxError> {
        self.check()?;
        let sources = self
            .0
            .sources
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        sources
            .as_ref()
            .ok_or_else(|| {
                BoxError::from(SuperviseError::Control {
                    reason: "storage-enabled launch has no shared source helper".into(),
                })
            })?
            .subscription(roots)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn configure_hosted(
        &self,
        paths: Vec<(std::path::PathBuf, bool)>,
    ) -> Result<(), BoxError> {
        let view = Arc::new(
            box_shell::StorageView::new(paths)
                .map_err(|source| SuperviseError::Spawn { source })?,
        );
        self.admit(|| {
            let mut hosted = self
                .0
                .hosted
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if hosted.is_some() {
                return Err(SuperviseError::Control {
                    reason: "hosted storage layout was already registered".into(),
                }
                .into());
            }
            let launcher =
                launcher::Launcher::start().map_err(|source| SuperviseError::Spawn { source })?;
            *self
                .0
                .launcher
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = Some(launcher);
            *hosted = Some(view);
            Ok(())
        })
    }

    /// Spawn only a prepared containment command, while the caller holds admission.
    #[cfg(target_os = "linux")]
    pub(crate) fn spawn_contained_command(
        &self,
        mut command: tokio::process::Command,
    ) -> std::io::Result<tokio::process::Child> {
        let launcher = self
            .0
            .launcher
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match launcher.as_ref() {
            Some(launcher) => launcher.spawn(command),
            None => command.spawn(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn hosted_view(&self) -> Option<Arc<box_shell::StorageView>> {
        self.0
            .hosted
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn install_hosted(&self, root: std::fs::File) -> Result<(), BoxError> {
        self.admit(|| {
            let view = self.hosted_view().ok_or_else(|| SuperviseError::Control {
                reason: "agent storage view has no registered hosted layout".into(),
            })?;
            view.install(root).map_err(|source| {
                SuperviseError::Control {
                    reason: format!("invalid agent storage view: {source}"),
                }
                .into()
            })
        })
    }

    fn close_hosted(&self) {
        #[cfg(target_os = "linux")]
        {
            if let Some(sources) = self
                .0
                .sources
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_mut()
            {
                sources.close();
            }
            if let Some(view) = self.hosted_view() {
                view.close();
            }
            if let Some(launcher) = self
                .0
                .launcher
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_mut()
            {
                launcher.close();
            }
        }
    }

    /// Refuse work after storage admission fails or the Box starts shutdown.
    pub(crate) fn check(&self) -> Result<(), BoxError> {
        self.admit(|| Ok(()))
    }

    /// Commit one short synchronous operation while admission remains open.
    pub(crate) fn admit<T>(
        &self,
        commit: impl FnOnce() -> Result<T, BoxError>,
    ) -> Result<T, BoxError> {
        let admission = self.lock_admission();
        if admission.closed {
            return Err(refusal(&admission));
        }
        // Do not call another owner method from `commit`; classify any returned error afterward.
        // Keep provider I/O, compilation, and waits outside this critical section. A control
        // message alone is not publication: a separate helper must join the same transaction
        // through its trusted protocol before the caller can claim a protected publication.
        // A panic must close admission before Tokio or another caller catches the unwind.
        // The failed state is never reused, so resuming the panic cannot preserve an open gate.
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(commit)) {
            Ok(result) => result,
            Err(payload) => {
                let mut admission = admission;
                self.latch_failure(
                    &mut admission,
                    "trusted storage admission commit panicked".into(),
                );
                drop(admission);
                std::panic::resume_unwind(payload)
            }
        }
    }

    /// Preserve the first admission failure and notify the Box's supervisor once.
    pub(crate) fn fail(&self, reason: impl Display) {
        let mut admission = self.lock_admission();
        self.latch_failure(&mut admission, reason.to_string());
    }

    fn lock_admission(&self) -> MutexGuard<'_, Admission> {
        match self.0.admission.lock() {
            Ok(admission) => admission,
            Err(poisoned) => {
                let mut admission = poisoned.into_inner();
                self.latch_failure(
                    &mut admission,
                    "storage admission state was poisoned".into(),
                );
                admission
            }
        }
    }

    fn latch_failure(&self, admission: &mut Admission, reason: String) {
        if admission.failure.is_some() {
            return;
        }
        admission.failure = Some(reason);
        admission.closed = true;
        self.0.closed.send_replace(true);
        self.close_hosted();
        self.cancel_workers();
        let _ = self.0.fatal.send(refusal(admission));
    }

    /// Wait for shutdown or a storage admission failure without waiting for storage readiness.
    pub(crate) async fn closed(&self) -> BoxError {
        let mut closed = self.0.closed.subscribe();
        let already_closed = *closed.borrow_and_update();
        if !already_closed {
            let _ = closed.changed().await;
        }
        let admission = self.lock_admission();
        refusal(&admission)
    }

    /// Cancel an in-flight launch when the shared Box owner closes admission.
    pub(crate) async fn while_open<T>(
        &self,
        operation: impl Future<Output = Result<T, BoxError>>,
    ) -> Result<T, BoxError> {
        tokio::select! {
            biased;
            failure = self.closed() => Err(failure),
            result = operation => result,
        }
    }

    /// Stop new admissions without treating normal teardown as a failure.
    pub(super) fn close(&self) {
        let mut admission = self.lock_admission();
        admission.closed = true;
        self.0.closed.send_replace(true);
        self.close_hosted();
        self.cancel_workers();
    }

    fn cancel_workers(&self) {
        for worker in self
            .0
            .workers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
        {
            worker.cancel.cancel();
        }
    }

    /// Own one blocking controller until normal shutdown has joined it.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn spawn_worker(
        &self,
        cancel: Arc<Cancellation>,
        run: impl FnOnce() -> Result<(), BoxError> + Send + 'static,
    ) -> Result<(), BoxError> {
        self.reap_finished();
        self.admit(|| {
            let owner = self.clone();
            let worker_cancel = Arc::clone(&cancel);
            let join = std::thread::Builder::new()
                .name("box-storage".into())
                .spawn(
                    move || match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
                        Ok(Ok(())) => {}
                        Ok(Err(error))
                            if error.is_storage_cancelled() && worker_cancel.is_cancelled() => {}
                        Ok(Err(error)) => owner.fail(error),
                        Err(_) => owner.fail("trusted storage controller panicked"),
                    },
                )
                .map_err(|source| SuperviseError::Spawn { source })?;
            self.0
                .workers
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(Worker { cancel, join });
            Ok(())
        })
    }

    #[cfg(any(target_os = "linux", test))]
    fn reap_finished(&self) {
        let completed = {
            let mut workers = self
                .0
                .workers
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let mut completed = Vec::new();
            let mut index = 0;
            while index < workers.len() {
                if workers[index].join.is_finished() {
                    completed.push(workers.swap_remove(index));
                } else {
                    index += 1;
                }
            }
            completed
        };
        for worker in completed {
            if worker.join.join().is_err() {
                self.fail("trusted storage controller could not be joined");
            }
        }
    }

    /// Report a stored failure after all owned admission workers have stopped.
    pub(super) fn finish(&self) -> Result<(), BoxError> {
        #[cfg(target_os = "linux")]
        {
            let sources = self
                .0
                .sources
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take();
            if let Some(mut sources) = sources
                && let Err(error) = sources.finish()
            {
                self.fail(error);
            }
            let launcher = self
                .0
                .launcher
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take();
            if let Some(mut launcher) = launcher
                && let Err(error) = launcher.finish()
            {
                self.fail(error);
            }
        }
        let workers = std::mem::take(
            &mut *self
                .0
                .workers
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        );
        for worker in workers {
            worker.cancel.cancel();
            if worker.join.join().is_err() {
                self.fail("trusted storage controller could not be joined");
            }
        }
        let admission = self.lock_admission();
        match &admission.failure {
            Some(_) => Err(refusal(&admission)),
            None => Ok(()),
        }
    }

    #[cfg(test)]
    pub(crate) fn testing() -> Self {
        let (fatal, _) = tokio::sync::mpsc::unbounded_channel();
        Self::new(fatal)
    }
}

pub(super) struct StartupGuard(Option<StorageOwner>);

impl StartupGuard {
    pub(super) fn disarm(mut self) {
        self.0.take();
    }
}

impl Drop for StartupGuard {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            owner.close();
            if let Err(error) = owner.finish() {
                eprintln!("strands-box: storage cleanup after startup failure: {error}");
            }
        }
    }
}

struct Worker {
    cancel: Arc<Cancellation>,
    join: std::thread::JoinHandle<()>,
}

/// Closing these private sockets interrupts controller and compiler waits without a readiness timer.
#[derive(Default)]
pub(crate) struct Cancellation {
    cancelled: std::sync::atomic::AtomicBool,
    sockets: Mutex<Vec<(u64, std::os::unix::net::UnixStream)>>,
    #[cfg(any(target_os = "linux", test))]
    next_socket: std::sync::atomic::AtomicU64,
}

impl Cancellation {
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Acquire)
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn track(&self, socket: &std::os::unix::net::UnixStream) -> std::io::Result<u64> {
        let mut sockets = self
            .sockets
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.is_cancelled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "storage controller stopped",
            ));
        }
        let id = self
            .next_socket
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |value| value.checked_add(1),
            )
            .map_err(|_| std::io::Error::other("storage cancellation registration overflow"))?;
        sockets.push((id, socket.try_clone()?));
        Ok(id)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn untrack(&self, id: u64) {
        self.sockets
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .retain(|(candidate, _)| *candidate != id);
    }

    pub(crate) fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        for (_, socket) in self
            .sockets
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .drain(..)
        {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
    }
}

fn refusal(admission: &Admission) -> BoxError {
    match &admission.failure {
        Some(reason) => SuperviseError::Control {
            reason: format!("storage admission: {reason}"),
        }
        .into(),
        None => SuperviseError::StorageCancelled.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn owner() -> (StorageOwner, tokio::sync::mpsc::UnboundedReceiver<BoxError>) {
        let (fatal, receiver) = tokio::sync::mpsc::unbounded_channel();
        (StorageOwner::new(fatal), receiver)
    }

    #[cfg(target_os = "linux")]
    fn credential_fields() -> Vec<String> {
        std::fs::read_to_string("/proc/thread-self/status")
            .unwrap()
            .lines()
            .filter(|line| {
                [
                    "Uid:",
                    "Gid:",
                    "Groups:",
                    "CapInh:",
                    "CapPrm:",
                    "CapEff:",
                    "CapBnd:",
                    "CapAmb:",
                    "NoNewPrivs:",
                ]
                .iter()
                .any(|field| line.starts_with(field))
            })
            .map(str::to_owned)
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_caller_can_launch_after_hosted_serving_drops_capabilities() {
        use std::os::unix::process::CommandExt as _;
        const CHILD: &str = "BOX_HOSTED_ROOT_LAUNCH_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new("unshare")
                .args(["--user", "--map-root-user", "--"])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", "run::hosted::storage::tests::root_caller_can_launch_after_hosted_serving_drops_capabilities", "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "root-user namespace control failed: {} {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        }
        // SAFETY: reading the calling thread's real UID has no side effect.
        assert_eq!(unsafe { libc::getuid() }, 0);
        let parent = credential_fields();
        let (owner, _) = owner();
        owner
            .configure_hosted(vec![("/incoming".into(), true)])
            .unwrap();
        let serving = owner.clone();
        std::thread::spawn(move || {
            containment::storage::drop_hosted_capabilities().unwrap();
            let credentials = credential_fields();
            for key in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
                assert!(credentials.iter().any(|line| {
                    line.split_once(':').is_some_and(|(name, value)| {
                        format!("{name}:") == key
                            && u64::from_str_radix(value.trim(), 16).unwrap() == 0
                    })
                }));
            }
            assert!(
                credentials
                    .iter()
                    .any(|line| line.starts_with("NoNewPrivs:") && line.ends_with('1'))
            );
            let refused = std::process::Command::new("unshare")
                .args(["--user", "--map-root-user", "--", "/bin/true"])
                .output()
                .unwrap();
            assert!(
                !refused.status.success(),
                "the direct hardened-thread control must refuse the UID0 map"
            );
            assert!(String::from_utf8_lossy(&refused.stderr).contains("uid_map"));
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let mut command = tokio::process::Command::new("unshare");
                command
                    .args(["--user", "--map-root-user", "--", "/bin/true"])
                    .kill_on_drop(true);
                command.as_std_mut().process_group(0);
                let mut child = serving
                    .admit(|| {
                        serving
                            .spawn_contained_command(command)
                            .map_err(|source| SuperviseError::Spawn { source }.into())
                    })
                    .unwrap();
                assert!(child.wait().await.unwrap().success());
            });
            assert_eq!(
                credential_fields(),
                credentials,
                "launch must not restore serving capabilities"
            );
        })
        .join()
        .unwrap();
        assert_eq!(
            credential_fields(),
            parent,
            "caller credentials must stay unchanged"
        );
        owner.close();
        owner.finish().unwrap();
        assert!(owner.0.launcher.lock().unwrap().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_close_and_failure_stop_and_join_the_launch_thread() {
        for fail in [false, true] {
            let (owner, _) = owner();
            owner
                .configure_hosted(vec![("/incoming".into(), true)])
                .unwrap();
            if fail {
                owner.fail("captured source refused");
            } else {
                owner.close();
            }
            assert!(owner.admit(|| Ok(())).is_err());
            assert!(owner.0.launcher.lock().unwrap().as_ref().is_some());
            assert_eq!(owner.finish().is_err(), fail);
            assert!(owner.0.launcher.lock().unwrap().is_none());
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn closing_admission_keeps_launch_parent_alive_until_children_stop() {
        use std::os::unix::process::ExitStatusExt as _;
        for (fail, premature_thread_exit) in [(false, true), (false, false), (true, false)] {
            let (owner, _) = owner();
            owner
                .configure_hosted(vec![("/incoming".into(), true)])
                .unwrap();
            let mut command = tokio::process::Command::new("/bin/cat");
            command
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .kill_on_drop(true);
            crate::run::contain::supervise::isolate(&mut command);
            let mut child = owner
                .admit(|| {
                    owner
                        .spawn_contained_command(command)
                        .map_err(|source| SuperviseError::Spawn { source }.into())
                })
                .unwrap();
            // Child::wait closes its own stdin; retain the pipe separately so a natural
            // EOF cannot impersonate a parent-death signal in this lifetime control.
            let input = child.stdin.take().unwrap();
            if fail {
                owner.fail("captured source refused");
            } else {
                owner.close();
            }
            if premature_thread_exit {
                // Model the old ordering explicitly: ending the spawning thread must
                // kill this otherwise-live child by its configured parent-death signal.
                owner
                    .0
                    .launcher
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .finish()
                    .unwrap();
                let status = tokio::time::timeout(std::time::Duration::from_secs(1), child.wait())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(status.signal(), Some(libc::SIGKILL));
            } else {
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(100), child.wait())
                        .await
                        .is_err(),
                    "closing admission must retain the child's spawning thread"
                );
                child.start_kill().unwrap();
                child.wait().await.unwrap();
            }
            drop(input);
            assert_eq!(owner.finish().is_err(), fail);
            assert!(owner.0.launcher.lock().unwrap().is_none());
        }
    }

    #[test]
    fn panicking_commit_notifies_owner_before_the_panic_is_caught() {
        let (owner, mut fatal) = owner();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), BoxError> = owner.admit(|| panic!("commit failed"));
        }));
        assert!(panic.is_err());
        let failure = fatal
            .try_recv()
            .expect("panic must notify without a later admission call");
        assert!(failure.to_string().contains("commit panicked"));
        assert!(owner.admit(|| Ok(())).is_err());
        assert_eq!(owner.finish().unwrap_err().to_string(), failure.to_string());
        assert!(fatal.try_recv().is_err());
    }

    #[test]
    fn poisoned_state_cannot_reopen_admission_or_finish_successfully() {
        let (owner, mut fatal) = owner();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _state = owner.0.admission.lock().unwrap();
            panic!("state update failed");
        }));
        assert!(panic.is_err());
        let failure = owner
            .check()
            .expect_err("poisoned state must refuse admission");
        assert!(failure.to_string().contains("state was poisoned"));
        assert_eq!(fatal.try_recv().unwrap().to_string(), failure.to_string());
        assert_eq!(owner.finish().unwrap_err().to_string(), failure.to_string());
        assert!(fatal.try_recv().is_err());
    }

    #[test]
    fn first_failure_closes_admission_and_survives_an_unread_notification() {
        let (owner, mut fatal) = owner();
        let tool = owner.clone();
        let mcp = owner.clone();
        owner.fail("protection failed");
        tool.fail("later helper exit");
        let ran = AtomicBool::new(false);
        let failure = mcp
            .admit(|| {
                ran.store(true, Ordering::SeqCst);
                Ok(())
            })
            .expect_err("a failed owner cannot launch or publish");
        assert!(!ran.load(Ordering::SeqCst));
        assert!(failure.to_string().contains("protection failed"));
        // The supervisor can observe normal workload exit before reading its fatal channel.
        owner.close();
        assert_eq!(owner.finish().unwrap_err().to_string(), failure.to_string());
        assert_eq!(fatal.try_recv().unwrap().to_string(), failure.to_string());
        assert!(matches!(
            fatal.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn failure_reported_while_shutdown_joins_workers_is_retained() {
        let (owner, mut fatal) = owner();
        owner.close();
        owner.fail("admission worker failed before it joined");
        let failure = owner
            .finish()
            .expect_err("shutdown must retain the worker failure");
        assert!(
            failure
                .to_string()
                .contains("admission worker failed before it joined")
        );
        assert_eq!(fatal.try_recv().unwrap().to_string(), failure.to_string());
    }

    #[test]
    fn pending_and_ordinary_operation_errors_do_not_fail_the_owner() {
        let (owner, mut fatal) = owner();
        owner.check().unwrap();
        let error: Result<(), BoxError> = owner.admit(|| {
            Err(SuperviseError::Control {
                reason: "ordinary tool error".into(),
            }
            .into())
        });
        assert!(error.is_err());
        assert_eq!(owner.admit(|| Ok(17)).unwrap(), 17);
        owner.finish().unwrap();
        assert!(matches!(
            fatal.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn close_cancels_an_inflight_launch_without_reporting_failure() {
        let (owner, mut fatal) = owner();
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let waiting = owner.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let operation_dropped = Arc::clone(&dropped);
        let (started, start) = tokio::sync::oneshot::channel();
        let operation = tokio::spawn(async move {
            waiting
                .while_open(async move {
                    let _dropped = Dropped(operation_dropped);
                    started.send(()).unwrap();
                    std::future::pending::<Result<(), BoxError>>().await
                })
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), start)
            .await
            .unwrap()
            .unwrap();
        assert!(!dropped.load(Ordering::SeqCst));
        owner.close();
        let failure = tokio::time::timeout(std::time::Duration::from_secs(1), operation)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(failure.to_string().contains("the Box is stopping"));
        assert!(
            dropped.load(Ordering::SeqCst),
            "closure must drop the started operation"
        );
        owner.finish().unwrap();
        assert!(owner.check().is_err());
        assert!(matches!(
            fatal.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn closure_before_wait_registration_is_not_lost() {
        let (owner, _) = owner();
        owner.fail("helper crashed");
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), owner.closed())
            .await
            .unwrap();
        assert!(error.to_string().contains("helper crashed"));
    }

    #[test]
    fn concurrent_failures_keep_one_reason_and_one_notification() {
        let (owner, mut fatal) = owner();
        let start = Arc::new(std::sync::Barrier::new(3));
        std::thread::scope(|scope| {
            for reason in ["agent admission", "MCP admission"] {
                let start = Arc::clone(&start);
                let owner = owner.clone();
                scope.spawn(move || {
                    start.wait();
                    owner.fail(reason);
                });
            }
            start.wait();
        });
        let failure = owner.finish().unwrap_err().to_string();
        assert_eq!(fatal.try_recv().unwrap().to_string(), failure);
        assert!(failure.contains("agent admission") || failure.contains("MCP admission"));
        assert!(matches!(
            fatal.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn admission_commit_and_failure_have_one_order() {
        let (owner, _) = owner();
        let (entered, started) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let committed = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let committing = owner.clone();
            let committed = &committed;
            let commit = scope.spawn(move || {
                committing.admit(|| {
                    entered.send(()).unwrap();
                    released.recv().unwrap();
                    committed.store(true, Ordering::SeqCst);
                    Ok(())
                })
            });
            started.recv().unwrap();
            assert!(matches!(
                owner.0.admission.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            let failing = owner.clone();
            let (attempt, attempted) = std::sync::mpsc::channel();
            let (finished, finish) = std::sync::mpsc::channel();
            let failure = scope.spawn(move || {
                attempt.send(()).unwrap();
                failing.fail("mount protection failed");
                finished.send(()).unwrap();
            });
            attempted.recv().unwrap();
            assert!(matches!(
                finish.recv_timeout(std::time::Duration::from_millis(25)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            assert!(!committed.load(Ordering::SeqCst));
            release.send(()).unwrap();
            commit.join().unwrap().unwrap();
            failure.join().unwrap();
        });
        assert!(committed.load(Ordering::SeqCst));
        assert!(owner.admit(|| Ok(())).is_err());
    }
}

#[cfg(test)]
mod worker_tests {
    use super::*;
    use std::io::Read;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn failed_startup_cancels_and_joins_storage_workers_before_returning() {
        let (fatal, mut failures) = tokio::sync::mpsc::unbounded_channel();
        let owner = StorageOwner::new(fatal);
        let weak = Arc::downgrade(&owner.0);
        let guard = owner.startup_guard();
        let cancel = Arc::new(Cancellation::default());
        let (mut waiting, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        cancel.track(&waiting).unwrap();
        let joined = Arc::new(AtomicBool::new(false));
        let completed = Arc::clone(&joined);
        owner
            .spawn_worker(cancel, move || {
                let _ = waiting.read(&mut [0]);
                completed.store(true, Ordering::Release);
                Err(SuperviseError::StorageCancelled.into())
            })
            .unwrap();
        drop(owner);
        drop(guard);
        assert!(joined.load(Ordering::Acquire));
        assert!(
            weak.upgrade().is_none(),
            "failed startup retained its storage owner"
        );
        assert!(failures.try_recv().is_err());
    }

    #[test]
    fn successful_startup_transfers_cleanup_to_the_hosted_box() {
        let (fatal, _) = tokio::sync::mpsc::unbounded_channel();
        let owner = StorageOwner::new(fatal);
        owner.startup_guard().disarm();
        owner
            .check()
            .expect("successful construction keeps admission open");
        owner.close();
        owner.finish().unwrap();
    }

    #[test]
    fn shutdown_interrupts_and_joins_a_controller_waiting_for_storage() {
        let (fatal, mut failures) = tokio::sync::mpsc::unbounded_channel();
        let owner = StorageOwner::new(fatal);
        let cancel = Arc::new(Cancellation::default());
        let (mut waiting, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        cancel.track(&waiting).unwrap();
        let joined = Arc::new(AtomicBool::new(false));
        let completed = Arc::clone(&joined);
        owner
            .spawn_worker(cancel, move || {
                let mut byte = [0];
                let _ = waiting.read(&mut byte);
                completed.store(true, Ordering::Release);
                Err(SuperviseError::StorageCancelled.into())
            })
            .unwrap();
        owner.close();
        owner.finish().unwrap();
        assert!(joined.load(Ordering::Acquire));
        assert!(failures.try_recv().is_err());
    }

    #[test]
    fn unexpected_controller_failure_closes_the_box_and_is_reported_after_join() {
        let (fatal, mut failures) = tokio::sync::mpsc::unbounded_channel();
        let owner = StorageOwner::new(fatal);
        owner
            .spawn_worker(Arc::new(Cancellation::default()), || {
                Err(SuperviseError::Control {
                    reason: "compiler died".into(),
                }
                .into())
            })
            .unwrap();
        let error = failures
            .blocking_recv()
            .expect("controller failure reaches owner");
        assert!(error.to_string().contains("compiler died"));
        assert!(owner.check().is_err());
        owner.close();
        assert!(
            owner
                .finish()
                .unwrap_err()
                .to_string()
                .contains("compiler died")
        );
    }

    #[test]
    fn cancellation_refuses_a_new_compiler_socket() {
        let cancel = Cancellation::default();
        cancel.cancel();
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(
            cancel.track(&socket).unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
    }

    #[test]
    fn an_already_computed_failure_survives_concurrent_normal_shutdown() {
        let (fatal, _failures) = tokio::sync::mpsc::unbounded_channel();
        let owner = StorageOwner::new(fatal);
        let (prepared, ready) = std::sync::mpsc::channel();
        let (release, wait) = std::sync::mpsc::channel();
        owner
            .spawn_worker(Arc::new(Cancellation::default()), move || {
                let failure: BoxError = SuperviseError::Control {
                    reason: "invalid compiled protection".into(),
                }
                .into();
                prepared.send(()).unwrap();
                wait.recv().unwrap();
                Err(failure)
            })
            .unwrap();
        ready.recv().unwrap();
        owner.close();
        release.send(()).unwrap();
        assert!(
            owner
                .finish()
                .unwrap_err()
                .to_string()
                .contains("invalid compiled protection")
        );
    }

    #[test]
    fn completed_controller_records_are_reaped_before_another_launch() {
        let (fatal, _failures) = tokio::sync::mpsc::unbounded_channel();
        let owner = StorageOwner::new(fatal);
        for _ in 0..32 {
            let (finished, wait) = std::sync::mpsc::channel();
            owner
                .spawn_worker(Arc::new(Cancellation::default()), move || {
                    finished.send(()).unwrap();
                    Ok(())
                })
                .unwrap();
            wait.recv().unwrap();
            while !owner
                .0
                .workers
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .join
                .is_finished()
            {
                std::thread::yield_now();
            }
            assert!(owner.0.workers.lock().unwrap().len() <= 1);
        }
        owner.close();
        owner.finish().unwrap();
        assert!(owner.0.workers.lock().unwrap().is_empty());
    }
}
