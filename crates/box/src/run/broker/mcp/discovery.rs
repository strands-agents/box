//! The stdio door's share of discovery: the shared tool catalogs, and when the door is done.

use std::collections::BTreeSet;
use std::io;
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use policy::{
    CatalogRefusal, CatalogStage, CompleteCatalog, DiscoveryFailure, ListPage, McpServerKind,
    PolicyStagingError, ServerDiscovery, ToolCatalogs,
};
use serde_json::{Value, json};

use super::super::complete::{DiscoveryCoordinator, DiscoveryDoor};
use crate::record::config::mcp::McpServer;

/// The most text one failure response can contain.
const MAXIMUM_DISCOVERY_FAILURE_BYTES: usize = 64 * 1024;

/// Whether the stdio door has reported itself done.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum CompletionOutcome {
    Pending,
    Finished,
    Closing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionState {
    Pending,
    Claimed,
    Finished,
}

struct RegistryState {
    closing: bool,
    completion: CompletionState,
}

struct RegistryJobs {
    accepting: bool,
    handles: Vec<std::thread::JoinHandle<()>>,
}

/// What staging one complete list did, for the exchange that holds its reply.
pub(super) enum StagedList {
    /// The reply may reach the client.
    Released,
    /// The reply is replaced by this failure.
    Failed(DiscoveryFailure),
    /// The box is stopping.
    Closing,
}

#[cfg(test)]
type StagingHook = Arc<dyn Fn(&str) + Send + Sync>;

#[cfg(test)]
#[derive(Default)]
struct RegistryTestHooks {
    before_staging: Mutex<Option<StagingHook>>,
    completion_claims: AtomicUsize,
    fail_next_staging_durably: AtomicBool,
}

/// The stdio door's discovery state for one run.
pub(crate) struct DiscoveryRegistry {
    catalogs: Arc<ToolCatalogs>,
    declared: BTreeSet<String>,
    state: Mutex<RegistryState>,
    /// Replies that settle a server's discovery and have not reached the client.
    deliveries: AtomicUsize,
    jobs: Mutex<RegistryJobs>,
    completion: tokio::sync::watch::Sender<CompletionOutcome>,
    changes: tokio::sync::watch::Sender<u64>,
    fatal: tokio::sync::mpsc::UnboundedSender<crate::error::BoxError>,
    coordinator: Arc<DiscoveryCoordinator>,
    #[cfg(test)]
    hooks: RegistryTestHooks,
}

/// The owner of the run's stdio discovery, which joins its jobs on drop.
pub(crate) struct DiscoveryRegistryHost {
    registry: Arc<DiscoveryRegistry>,
    fatal: tokio::sync::mpsc::UnboundedReceiver<crate::error::BoxError>,
}

/// Held while a reply that settles discovery is on its way to the client.
pub(crate) struct DiscoveryReleaseGuard {
    registry: Weak<DiscoveryRegistry>,
}

impl Drop for DiscoveryReleaseGuard {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.deliveries.fetch_sub(1, Ordering::AcqRel);
            registry.request_completion_check();
        }
    }
}

impl DiscoveryRegistryHost {
    /// Start with a stdio-only coordinator and stdio-only catalogs.
    #[cfg(test)]
    pub(crate) fn start(
        declared: &[McpServer],
        policy: Arc<policy::PolicyEngine>,
    ) -> io::Result<Self> {
        let coordinator = DiscoveryCoordinator::testing(Arc::clone(&policy));
        let catalogs = Arc::new(ToolCatalogs::new(
            policy,
            declared
                .iter()
                .map(|server| (server.name.clone(), McpServerKind::Stdio)),
        ));
        Self::start_with_coordinator(declared, catalogs, coordinator)
    }

    /// Start the stdio door over the box's tool catalogs.
    pub(crate) fn start_with_coordinator(
        declared: &[McpServer],
        catalogs: Arc<ToolCatalogs>,
        coordinator: Arc<DiscoveryCoordinator>,
    ) -> io::Result<Self> {
        let (fatal, receiver) = tokio::sync::mpsc::unbounded_channel();
        let registry = DiscoveryRegistry::new(declared, catalogs, coordinator, fatal);
        let host = Self {
            registry,
            fatal: receiver,
        };
        host.registry.request_completion_check();
        Ok(host)
    }

    pub(crate) fn registry(&self) -> Arc<DiscoveryRegistry> {
        Arc::clone(&self.registry)
    }

    pub(crate) fn close(&self) {
        self.registry.close();
    }

    pub(crate) async fn stopped(&mut self) -> crate::error::BoxError {
        self.fatal
            .recv()
            .await
            .unwrap_or_else(|| crate::error::McpDiscoveryError::NoOutcome.into())
    }
}

impl Drop for DiscoveryRegistryHost {
    fn drop(&mut self) {
        self.registry.close();
        self.registry.join_jobs();
    }
}

impl DiscoveryRegistry {
    fn new(
        declared: &[McpServer],
        catalogs: Arc<ToolCatalogs>,
        coordinator: Arc<DiscoveryCoordinator>,
        fatal: tokio::sync::mpsc::UnboundedSender<crate::error::BoxError>,
    ) -> Arc<Self> {
        let (completion, _) = tokio::sync::watch::channel(CompletionOutcome::Pending);
        let (changes, _) = tokio::sync::watch::channel(0);
        Arc::new(Self {
            catalogs,
            declared: declared.iter().map(|server| server.name.clone()).collect(),
            state: Mutex::new(RegistryState {
                closing: false,
                completion: CompletionState::Pending,
            }),
            deliveries: AtomicUsize::new(0),
            jobs: Mutex::new(RegistryJobs {
                accepting: true,
                handles: Vec::new(),
            }),
            completion,
            changes,
            fatal,
            coordinator,
            #[cfg(test)]
            hooks: RegistryTestHooks::default(),
        })
    }

    /// A registry over `declared` and a permissive test policy, with no coordinator to report to.
    #[cfg(test)]
    pub(crate) fn testing(declared: &[McpServer]) -> Arc<Self> {
        let policy = Arc::new(crate::test_support::open_policy(Vec::new()));
        Self::testing_with_policy(declared, policy)
    }

    /// A registry over `declared` and `policy`, with no coordinator to report to.
    #[cfg(test)]
    pub(crate) fn testing_with_policy(
        declared: &[McpServer],
        policy: Arc<policy::PolicyEngine>,
    ) -> Arc<Self> {
        let (fatal, _failures) = tokio::sync::mpsc::unbounded_channel();
        let coordinator = DiscoveryCoordinator::testing(Arc::clone(&policy));
        let catalogs = Arc::new(ToolCatalogs::new(
            policy,
            declared
                .iter()
                .map(|server| (server.name.clone(), McpServerKind::Stdio)),
        ));
        Self::new(declared, catalogs, coordinator, fatal)
    }

    /// Refuse a connection to an undeclared server, or to one whose discovery failed.
    pub(crate) fn admit_open(&self, server: &str) -> io::Result<()> {
        if self.lock().closing {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "MCP discovery is closing",
            ));
        }
        if !self.declared.contains(server) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("MCP server {server:?} is not declared"),
            ));
        }
        match self.catalogs.state(server) {
            Some(ServerDiscovery::Failed(failure))
                if failure != DiscoveryFailure::ToolsListDenied =>
            {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("MCP server {server:?} failed during {failure}"),
                ))
            }
            _ => Ok(()),
        }
    }

    /// Where one server's discovery stands.
    pub(super) fn discovery(&self, server: &str) -> Option<ServerDiscovery> {
        self.catalogs.state(server)
    }

    /// Refuse a `tools/call` the server's accepted catalog does not name.
    pub(crate) fn require_listed(&self, server: &str, tool: &str) -> Result<(), CatalogRefusal> {
        self.catalogs.require_listed(server, tool)
    }

    /// Record a policy refusal of a server's `tools/list`.
    pub(super) fn list_denied(self: &Arc<Self>, server: &str) {
        self.catalogs.list_denied(server);
        self.changed();
    }

    /// Observe one reply to a client's `tools/list`.
    pub(super) fn observe_page(
        self: &Arc<Self>,
        server: &str,
        connection: &str,
        cursor: Option<&str>,
        response: &Value,
        bytes: usize,
    ) -> Result<ListPage, DiscoveryFailure> {
        let page = self
            .catalogs
            .observe_page(server, connection, cursor, response, bytes);
        if page.is_err() {
            self.changed();
        }
        page
    }

    /// Record a captured list that failed for a reason its reply does not show.
    pub(super) fn list_failed(
        self: &Arc<Self>,
        server: &str,
        connection: &str,
        failure: DiscoveryFailure,
    ) {
        self.catalogs.list_failed(server, connection, failure);
        self.changed();
    }

    /// Drop the unfinished lists of a closed connection.
    pub(super) fn connection_closed(&self, connection: &str) {
        self.catalogs.connection_closed(connection);
    }

    /// Hold the discovery door open until the returned guard drops.
    pub(super) fn delivery(self: &Arc<Self>) -> DiscoveryReleaseGuard {
        self.deliveries.fetch_add(1, Ordering::AcqRel);
        DiscoveryReleaseGuard {
            registry: Arc::downgrade(self),
        }
    }

    /// Stage one complete list on a job thread the registry joins at teardown.
    pub(super) fn stage(
        self: &Arc<Self>,
        catalog: CompleteCatalog,
    ) -> impl std::future::Future<Output = StagedList> + 'static {
        let (sender, staged) = tokio::sync::oneshot::channel();
        let spawned = self.spawn_job("strands-box-mcp-staging".to_string(), move |registry| {
            let _ = sender.send(registry.stage_now(catalog));
        });
        if let Err(source) = &spawned
            && !self.lock().closing
        {
            self.fatal(
                crate::error::McpDiscoveryError::Thread {
                    source: io::Error::new(source.kind(), source.to_string()),
                }
                .into(),
            );
        }
        async move {
            match spawned {
                Ok(()) => staged.await.unwrap_or(StagedList::Closing),
                Err(_) => StagedList::Closing,
            }
        }
    }

    /// Whether a reply to this `tools/list` would be captured.
    pub(super) fn captures(&self, server: &str, connection: &str, cursor: Option<&str>) -> bool {
        self.catalogs.captures(server, connection, cursor)
    }

    fn stage_now(self: &Arc<Self>, catalog: CompleteCatalog) -> StagedList {
        if self.lock().closing {
            return StagedList::Closing;
        }
        let server = catalog_server(&catalog);
        #[cfg(test)]
        self.run_staging_hook(&server);
        let tools = catalog.tool_count();
        let staged = self.stage_with_test_faults(catalog);
        let outcome = match staged {
            Ok(CatalogStage::Accepted { .. }) => {
                self.coordinator.control(
                    telemetry::ControlRecord::completed(
                        telemetry::ControlOperation::SchemaInstalled,
                        &server,
                    )
                    .detailed(&format!("{tools} tools")),
                );
                StagedList::Released
            }
            Ok(CatalogStage::Unchanged) => StagedList::Released,
            Ok(CatalogStage::Rejected { failure, reason }) => {
                match failure {
                    DiscoveryFailure::SchemaGeneration => eprintln!(
                        "strands-box: warning: MCP server {server:?} schema generation failed: \
                         {reason}"
                    ),
                    DiscoveryFailure::PolicyStaging => {
                        eprintln!(
                            "strands-box: warning: MCP server {server:?} policy staging failed: \
                             {reason}"
                        );
                        self.coordinator.control(telemetry::ControlRecord::refused(
                            telemetry::ControlOperation::SchemaInstalled,
                            &server,
                            &reason,
                        ));
                    }
                    _ => {}
                }
                StagedList::Failed(failure)
            }
            Err(error) => {
                self.coordinator.control(telemetry::ControlRecord::refused(
                    telemetry::ControlOperation::SchemaInstalled,
                    &server,
                    &error.to_string(),
                ));
                self.fatal(error.into());
                StagedList::Closing
            }
        };
        self.changed();
        outcome
    }

    #[cfg(not(test))]
    fn stage_with_test_faults(
        &self,
        catalog: CompleteCatalog,
    ) -> Result<CatalogStage, PolicyStagingError> {
        self.catalogs.stage(catalog)
    }

    #[cfg(test)]
    fn stage_with_test_faults(
        &self,
        catalog: CompleteCatalog,
    ) -> Result<CatalogStage, PolicyStagingError> {
        if self
            .hooks
            .fail_next_staging_durably
            .swap(false, Ordering::AcqRel)
        {
            return Err(PolicyStagingError::Durable(
                "injected durable staging failure".to_string(),
            ));
        }
        self.catalogs.stage(catalog)
    }

    pub(crate) fn completion(&self) -> tokio::sync::watch::Receiver<CompletionOutcome> {
        self.completion.subscribe()
    }

    pub(super) fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }

    fn changed(self: &Arc<Self>) {
        self.changes.send_modify(|revision| {
            *revision = revision.saturating_add(1);
        });
        self.request_completion_check();
    }

    fn close(&self) {
        {
            let mut state = self.lock();
            if state.closing {
                return;
            }
            state.closing = true;
        }
        self.completion.send_replace(CompletionOutcome::Closing);
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.accepting = false;
        }
    }

    pub(super) fn request_completion_check(self: &Arc<Self>) {
        {
            let mut state = self.lock();
            if state.closing
                || state.completion != CompletionState::Pending
                || self.deliveries.load(Ordering::Acquire) != 0
                || !self.catalogs.kind_done(McpServerKind::Stdio)
            {
                return;
            }
            state.completion = CompletionState::Claimed;
        }
        #[cfg(test)]
        self.hooks.completion_claims.fetch_add(1, Ordering::AcqRel);

        let registry = Arc::clone(self);
        let spawn = self.spawn_job("strands-box-mcp-completion".to_string(), move |registry| {
            registry.finish_completion();
            registry.coordinator.report_finished(DiscoveryDoor::Stdio);
        });
        if let Err(source) = spawn
            && !self.lock().closing
        {
            registry.fatal(crate::error::McpDiscoveryError::Thread { source }.into());
        }
    }

    fn finish_completion(&self) {
        let mut state = self.lock();
        if !state.closing && state.completion == CompletionState::Claimed {
            state.completion = CompletionState::Finished;
            self.completion.send_replace(CompletionOutcome::Finished);
        }
    }

    fn fatal(&self, error: crate::error::BoxError) {
        self.close();
        let _ = self.fatal.send(error);
    }

    fn spawn_job(
        self: &Arc<Self>,
        name: String,
        work: impl FnOnce(Arc<DiscoveryRegistry>) + Send + 'static,
    ) -> io::Result<()> {
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| io::Error::other("MCP discovery job lock poisoned"))?;
        if !jobs.accepting {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "MCP discovery is closing",
            ));
        }
        let registry = Arc::clone(self);
        let panic_registry = Arc::clone(self);
        let handle = std::thread::Builder::new().name(name).spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(registry)));
            if result.is_err() {
                panic_registry.fatal(
                    crate::error::McpDiscoveryError::Thread {
                        source: io::Error::other("an MCP discovery job panicked"),
                    }
                    .into(),
                );
            }
        })?;
        jobs.handles.push(handle);
        Ok(())
    }

    fn join_jobs(&self) {
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.accepting = false;
        }
        loop {
            let handles = match self.jobs.lock() {
                Ok(mut jobs) => std::mem::take(&mut jobs.handles),
                Err(error) => std::mem::take(&mut error.into_inner().handles),
            };
            if handles.is_empty() {
                break;
            }
            for handle in handles {
                let _ = handle.join();
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RegistryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(crate) fn set_staging_hook(&self, hook: StagingHook) {
        *self.hooks.before_staging.lock().expect("staging hook lock") = Some(hook);
    }

    #[cfg(test)]
    fn run_staging_hook(&self, server: &str) {
        let hook = self
            .hooks
            .before_staging
            .lock()
            .expect("staging hook lock")
            .clone();
        if let Some(hook) = hook {
            hook(server);
        }
    }

    #[cfg(test)]
    pub(crate) fn completion_claims(&self) -> usize {
        self.hooks.completion_claims.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn testing_fail_next_staging_durably(&self) {
        self.hooks
            .fail_next_staging_durably
            .store(true, Ordering::Release);
    }

    /// Stage a one-tool catalog for `server` on a job thread, as a completed list would.
    #[cfg(test)]
    pub(crate) fn testing_stage_catalog(
        self: &Arc<Self>,
        server: &str,
        tool: &str,
    ) -> io::Result<()> {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": tool, "inputSchema": {"type": "object"}}]}
        });
        let page = self
            .observe_page(server, "testing", None, &response, 64)
            .map_err(|failure| io::Error::other(failure.to_string()))?;
        let ListPage::Complete(catalog) = page else {
            return Err(io::Error::other("the test catalog did not complete"));
        };
        let guard = self.delivery();
        self.spawn_job(
            "strands-box-mcp-test-staging".to_string(),
            move |registry| {
                registry.stage_now(catalog);
                drop(guard);
            },
        )
    }
}

fn catalog_server(catalog: &CompleteCatalog) -> String {
    catalog.server().to_string()
}

/// The JSON-RPC error a client receives when its server's discovery failed.
pub(super) fn failure_response(server: &str, failure: DiscoveryFailure, id: &Value) -> String {
    let message = format!("MCP server {server:?} failed during {failure}");
    let message = if message.len() > MAXIMUM_DISCOVERY_FAILURE_BYTES {
        "MCP server discovery failed".to_string()
    } else {
        message
    };
    format!(
        "{}\n",
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32002, "message": message}
        })
    )
}
