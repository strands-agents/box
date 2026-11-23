use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{Error, McpTarget, Pack, RunContext, mcp, packs};

/// The context collected during one run preparation.
pub struct ContextBuilder {
    context: RunContext,
}

impl ContextBuilder {
    /// System metadata and the CLI's normalized release version.
    pub fn new(version: &str) -> Result<Self, Error> {
        Ok(Self {
            context: RunContext::new(
                version,
                std::env::consts::OS,
                sysinfo::System::os_version().ok(),
                std::env::consts::ARCH,
            )?,
        })
    }

    /// The saved profile bytes and its policy declarations.
    pub fn profile(&mut self, bytes: &[u8]) {
        self.context.profile_hash = Some(format!("{:x}", Sha256::digest(bytes)));
        self.context.profile_policy_present = policy_present(bytes);
    }

    /// The stored MCP sections after configuration import.
    pub fn mcp<'a>(&mut self, home: &Path, targets: impl IntoIterator<Item = McpTarget<'a>>) {
        self.context.mcp_configured = mcp::configured(home, targets);
    }

    /// The complete contributing pack graph.
    pub fn packs<'a>(&mut self, loaded: impl IntoIterator<Item = Pack<'a>>) {
        (self.context.builtin_packs, self.context.has_custom_packs) = packs::classify(loaded);
    }

    /// The immutable context for the invocation's events.
    pub fn finish(self) -> RunContext {
        self.context
    }
}

fn policy_present(bytes: &[u8]) -> Option<bool> {
    let profile: toml::Table = toml::from_str(std::str::from_utf8(bytes).ok()?).ok()?;
    let Some(policies) = profile.get("policies") else {
        return Some(false);
    };
    let policies = policies.as_array()?;
    policies
        .iter()
        .all(|policy| {
            policy
                .as_str()
                .is_some_and(|path| !path.is_empty() && !path.contains("${{"))
        })
        .then_some(!policies.is_empty())
}
