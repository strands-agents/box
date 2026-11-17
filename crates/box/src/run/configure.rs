//! Store one validated configuration snapshot and materialize its aliases.

use crate::error::BoxError;
use crate::record::config::ConfigureRequest;
use crate::record::layout::BoxRoot;
use crate::run::broker;
use crate::run::lock::Lock;

/// Write a validated authority into an existing box root: record, policy, alias image.
pub(crate) fn write(
    root: &BoxRoot,
    request: &ConfigureRequest,
    owner: &Lock,
) -> Result<(), BoxError> {
    root.write_committed_record(&request.record.to_toml()?)?;
    match &request.policy {
        Some(source) => root.write_private_file(&root.policy(), &source.text, 0o400)?,
        // Removed rather than left: a `configure` that drops the policy must not
        // leave the previous one enforced, which is exactly what a stale file here
        None => {
            root.remove_file(&root.policy())?;
        }
    }
    // Box-lifetime, so it happens here and not at every `start`: an alias is an exec literal in a
    // profile and an entry on a process's `PATH`. Every declared server gets one.
    broker::aliases::materialize(root, &request.record.mcp, owner)?;
    Ok(())
}
