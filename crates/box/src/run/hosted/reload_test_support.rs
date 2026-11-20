//! Isolated fixtures for the process-owned reload entry point.

use std::sync::{Arc, mpsc};
use std::time::Duration;

use policy::{Policy, PolicyEngine};

use super::RUNNING_POLICY;

const CHILD_TEST: &str = "STRANDS_BOX_RELOAD_TEST";
const TIMEOUT: Duration = Duration::from_secs(10);

/// Run a registry-mutating test alone, without other hosted-box tests in the same process.
pub(crate) fn isolated(test_name: &str, test: impl FnOnce()) {
    if std::env::var(CHILD_TEST).as_deref() == Ok(test_name) {
        test();
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_TEST, test_name)
        .output()
        .expect("isolated reload test starts");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("running 1 test"),
        "isolated reload test failed: {}\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Install the same engine and collector handles that the hosted box registers for reload.
pub(crate) fn with_running_policy(policy: Arc<PolicyEngine>, test: impl FnOnce()) {
    assert!(
        std::env::var_os(CHILD_TEST).is_some(),
        "requires an isolated test"
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("collector runtime");
    let _entered = runtime.enter();
    let directory = tempfile::tempdir().expect("collector directory");
    let collector = Arc::new(
        ::telemetry::open(
            ::telemetry::TelemetryConfig::for_box("reload-test").with_target(
                ::telemetry::Target::new(
                    ::telemetry::TargetKind::File,
                    directory.path().join("records.jsonl").to_string_lossy(),
                ),
            ),
        )
        .expect("collector opens"),
    );
    assert!(
        RUNNING_POLICY
            .lock()
            .unwrap()
            .replace((policy, collector))
            .is_none()
    );
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            RUNNING_POLICY.lock().unwrap().take();
        }
    }
    let _clear = Clear;
    test();
}

pub(crate) struct ReloadProbe {
    result: mpsc::Receiver<Result<(), crate::ReloadRefused>>,
    worker: std::thread::JoinHandle<()>,
}

/// Start the public runtime reload on a worker while an admission is paused.
pub(crate) fn spawn_reload(sources: Vec<Policy>) -> ReloadProbe {
    let (started, ready) = mpsc::sync_channel(1);
    let (done, result) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        started.send(()).unwrap();
        done.send(crate::reload(&sources)).unwrap();
    });
    ready.recv_timeout(TIMEOUT).expect("reload worker starts");
    ReloadProbe { result, worker }
}

impl ReloadProbe {
    pub(crate) fn assert_waiting(&self) {
        assert!(
            matches!(
                self.result.recv_timeout(Duration::from_secs(3)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "reload must wait for the complete request admission",
        );
    }

    pub(crate) fn finish(self) -> Result<(), crate::ReloadRefused> {
        let result = self.result.recv_timeout(TIMEOUT).expect("reload completes");
        self.worker.join().expect("reload worker joins");
        result
    }
}
