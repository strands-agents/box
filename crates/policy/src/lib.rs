//! `strands-box-policy` — the slice's single local Policy Decision Point (PDP).

#![warn(missing_docs, unreachable_pub)]

mod adapters;
mod address;
mod cap;
mod catalog;
mod decision;
mod dogwood;
mod error;
mod mcp_schema;
mod observe;
mod outcome;
mod path;
mod policy;
mod request;
#[cfg(test)]
mod rerun;
mod schema;
mod spelling;

#[cfg(feature = "egress-adapter")]
pub use adapters::egress::EgressPolicyInterceptor;
#[cfg(feature = "script-adapter")]
pub use adapters::script::{
    RenameDestination, ScriptPermit, ScriptPolicyInterceptor, ScriptRefusal,
};
#[cfg(feature = "shell-adapter")]
pub use adapters::shell::ShellPolicyInterceptor;
pub use catalog::{
    CatalogRefusal, CatalogStage, CompleteCatalog, DiscoveryFailure, ListPage, MAXIMUM_LIST_BYTES,
    MAXIMUM_LIST_PAGES, McpServerKind, ServerDiscovery, ToolCatalogs,
};
pub use decision::{Decision, DenyReason, PolicyAttribution, RuleId};
pub use dogwood::event_schema_source;
pub use error::{PolicyDiagnostic, PolicyError, PolicyStagingError};
pub use mcp_schema::{
    McpSchemaError, compose_action_schema, generate_mcp_schema, validate_mcp_schema_composition,
};
pub use observe::DecisionObserver;
pub use outcome::{Delivery, FsResult, Outcome};
pub use path::{ApprovedPath, PathRefusal, PathResolver};
pub use policy::{
    ENGINE_ID, EffectivePolicy, Policy, PolicyEngine, SELF_DEFENDED_FILES, SchemaStage,
};
pub use request::{FsAccess, FsOperation, Principal, Request};
pub use schema::GovernedBox;
pub use spelling::{Operator, PolicyWarning};
