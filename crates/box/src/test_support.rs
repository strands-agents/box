//! Shared policy fixtures for unit tests.

use std::cell::RefCell;

use policy::{Policy, PolicyEngine};
use tempfile::TempDir;

thread_local! {
    /// Directories that must outlive the policies which use their databases.
    static DATABASES: RefCell<Vec<TempDir>> = const { RefCell::new(Vec::new()) };
}

/// Open one policy against a fresh durable database.
pub(crate) fn open_policy(sources: Vec<Policy>) -> PolicyEngine {
    open_policy_with_mcp_schemas(sources, &[])
}

/// Open one policy with MCP schemas against a fresh durable database.
pub(crate) fn open_policy_with_mcp_schemas(
    sources: Vec<Policy>,
    mcp_schemas: &[String],
) -> PolicyEngine {
    let directory = tempfile::tempdir().expect("Dogwood database directory");
    let policy = PolicyEngine::open_with_mcp_schemas(
        sources,
        mcp_schemas,
        &directory.path().join("dogwood.redb"),
    )
    .expect("test policy opens");
    DATABASES.with_borrow_mut(|databases| databases.push(directory));
    policy
}

/// A `threat` entry of the `in-memory` kind that keeps `outputs` at `min_confidence`.
pub(crate) fn enrichment_entry(
    outputs: &[&str],
    min_confidence: crate::run::enrichment::Confidence,
) -> crate::record::config::enrichment::EnrichmentEntry {
    crate::record::config::enrichment::EnrichmentEntry {
        kind: "in-memory".to_string(),
        endpoint: "file:///unused.json".to_string(),
        secret: None,
        outputs: outputs.iter().map(|label| (*label).to_string()).collect(),
        min_confidence,
        timeout: std::time::Duration::from_millis(500),
        max_age: std::time::Duration::from_secs(300),
    }
}

/// The egress interceptor of a box whose policy is `text` and whose one `threat` entry asks
/// `source`, with the directory that holds its history.
pub(crate) fn enrichment_interceptor(
    text: &str,
    source: &std::sync::Arc<crate::run::enrichment::memory::InMemorySource>,
) -> (
    std::sync::Arc<dyn egress_gateway::EffectInterceptor>,
    TempDir,
) {
    use std::sync::Arc;

    use crate::run::enrichment::{Confidence, Enricher, Source};

    let directory = tempfile::tempdir().expect("a directory");
    let history = directory.path().join("dogwood.redb");
    let file = std::fs::File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&history)
        .expect("the history opens");
    let engine = Arc::new(
        PolicyEngine::open_staged_file_with_grammars(
            &policy::Operator::unanchored(),
            vec![Policy {
                origin: std::path::PathBuf::from("policy.dw"),
                text: text.to_string(),
            }],
            policy::ToolGrammars::default(),
            &policy::EnrichmentNames::new(["threat".to_string()]).expect("a name"),
            file,
            history,
        )
        .expect("the policy opens"),
    );
    let declared = std::collections::BTreeMap::from([(
        "threat".to_string(),
        enrichment_entry(&["malware"], Confidence::Low),
    )]);
    let enricher = Enricher::opening(&declared, engine.read_enrichment(), |_| {
        Ok(Arc::clone(source) as Arc<dyn Source>)
    })
    .expect("the enricher opens");
    let interceptor = policy::EgressPolicyInterceptor::into_handle_with_discovery(
        Arc::clone(&engine),
        policy::Principal::agent(),
        policy::GovernedBox::assigned("test-box"),
        Vec::new(),
        Arc::new(policy::ToolCatalogs::new(
            Arc::clone(&engine),
            Vec::<(String, policy::McpServerKind)>::new(),
        )),
        Arc::new(|| {}),
        Arc::new(enricher),
    );
    (interceptor, directory)
}

// One lock over `HOME` for every test in this module tree.

use std::path::Path;
use std::sync::Mutex;

static HOME_LOCK: Mutex<()> = Mutex::new(());

/// Run `body` with `HOME` pointed at `home`, restoring the previous value afterwards.
pub(crate) fn with_operator_home<T>(home: &Path, body: impl FnOnce() -> T) -> T {
    // A poisoned lock still protects the variable: the panicking test has already
    // restored it or is about to unwind past its own restore, and refusing to run every
    let _guard = HOME_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let previous = std::env::var_os("HOME");
    // SAFETY: the mutex serializes every mutation of HOME in this module tree, and the
    // original value is restored before the guard drops.
    unsafe { std::env::set_var("HOME", home) };
    let result = body();
    match previous {
        // SAFETY: as above.
        Some(value) => unsafe { std::env::set_var("HOME", value) },
        None => unsafe { std::env::remove_var("HOME") },
    }
    result
}

// Process fixtures shared by the supervise and hosted tests.

/// A leader and one descendant that both ignore `SIGTERM`, with their pids written to `"$1"`.
#[cfg(unix)]
pub(crate) const HELD_GROUP: &str =
    r#"trap '' TERM; sleep 3600 & printf '%s %s' "$$" "$!" > "$1"; wait"#;

/// Held by every test that raises a signal at this process or changes a signal's disposition,
/// because both are process-wide.
#[cfg(unix)]
pub(crate) static SIGNALS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(unix)]
pub(crate) fn process_exists(pid: libc::pid_t) -> bool {
    // SAFETY: signal zero only tests whether the process is still present.
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Whether every pid is gone within five seconds.
#[cfg(unix)]
pub(crate) async fn processes_exit(pids: &[libc::pid_t]) -> bool {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while pids.iter().copied().any(process_exists) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

/// The `count` pids a workload writes to `path`, or `None` after five seconds.
#[cfg(unix)]
pub(crate) async fn wait_for_pids(path: &Path, count: usize) -> Option<Vec<libc::pid_t>> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let pids = std::fs::read_to_string(path)
                .unwrap_or_default()
                .split_whitespace()
                .filter_map(|pid| pid.parse().ok())
                .collect::<Vec<_>>();
            if pids.len() == count {
                return pids;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .ok()
}
