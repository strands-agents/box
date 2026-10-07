//! Durable Dogwood databases for integration tests.

use std::cell::RefCell;

use policy::{Policy, PolicyEngine, PolicyError};
use tempfile::TempDir;

thread_local! {
    /// Directories that must outlive the policies which use their databases.
    static DATABASES: RefCell<Vec<TempDir>> = const { RefCell::new(Vec::new()) };
}

/// Open one policy against a fresh durable database.
pub(crate) fn open_policy(sources: Vec<Policy>) -> Result<PolicyEngine, PolicyError> {
    open_policy_with_mcp_schemas(sources, &[])
}

/// Open one policy with MCP schemas against a fresh durable database.
pub(crate) fn open_policy_with_mcp_schemas(
    sources: Vec<Policy>,
    mcp_schemas: &[String],
) -> Result<PolicyEngine, PolicyError> {
    let directory = tempfile::tempdir().expect("Dogwood database directory");
    let policy = PolicyEngine::open_with_mcp_schemas(
        sources,
        mcp_schemas,
        &directory.path().join("dogwood.redb"),
    )?;
    DATABASES.with_borrow_mut(|databases| databases.push(directory));
    Ok(policy)
}
