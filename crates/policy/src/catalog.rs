//! The tool catalog each declared MCP server lists, accepted only once its schema stages.
//!
//! | Step | Call |
//! |---|---|
//! | the server answers one page of a client's `tools/list` | [`ToolCatalogs::observe_page`] |
//! | the last page completes the catalog | [`ToolCatalogs::stage`] |
//! | a `tools/call` names a tool | [`ToolCatalogs::require_listed`] |
//! | policy refuses a `tools/list` | [`ToolCatalogs::list_denied`] |
//! | the connection that listed closes | [`ToolCatalogs::connection_closed`] |
//! | every server of one kind is terminal | [`ToolCatalogs::kind_done`] |

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::Value;

use crate::{PolicyEngine, PolicyStagingError, SchemaStage};

/// The most pages one `tools/list` can contain.
pub const MAXIMUM_LIST_PAGES: usize = 256;

/// The most response text one `tools/list` can contain.
pub const MAXIMUM_LIST_BYTES: usize = 8 * 1024 * 1024;

/// The most discovery data one run retains.
const MAXIMUM_RETAINED_BYTES: usize = 32 * 1024 * 1024;

/// The most unfinished lists one server can have at once.
const MAXIMUM_CONCURRENT_LISTS: usize = 4;

/// The most times one server's accepted catalog can change in one run.
const MAXIMUM_RESTAGES: usize = 16;

/// The kind of MCP server a catalog belongs to.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum McpServerKind {
    /// A server the box starts and speaks to over stdio.
    Stdio,
    /// A remote server the egress gateway reaches over HTTP.
    Http,
}

/// Where one server's discovery stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerDiscovery {
    /// No complete list has arrived.
    Undiscovered,
    /// A list is in progress, and no catalog is accepted.
    Listing,
    /// A catalog is accepted.
    Ready,
    /// Discovery failed, and no catalog is accepted.
    Failed(DiscoveryFailure),
}

/// Why one server's discovery failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryFailure {
    /// Policy refused the server's `tools/list`.
    ToolsListDenied,
    /// The server's reply was not a valid catalog page.
    CatalogCapture,
    /// The server did not reply in time.
    CaptureDeadline,
    /// The catalog did not produce a schema.
    SchemaGeneration,
    /// The policy refused the catalog's schema.
    PolicyStaging,
    /// The run's discovery budget is spent.
    RunRetention,
}

impl fmt::Display for DiscoveryFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ToolsListDenied => "tools/list denied by policy",
            Self::CatalogCapture => "catalog capture",
            Self::CaptureDeadline => "capture deadline",
            Self::SchemaGeneration => "schema generation",
            Self::PolicyStaging => "policy staging",
            Self::RunRetention => "run retention",
        })
    }
}

/// What one observed page did to its list.
#[derive(Debug)]
pub enum ListPage {
    /// The page is part of a captured list, and more pages follow.
    More,
    /// The page completed a captured list.
    Complete(CompleteCatalog),
    /// The page belongs to no captured list.
    Ignored,
}

/// One complete list, ready to stage.
#[derive(Debug)]
pub struct CompleteCatalog {
    server: String,
    tools: BTreeSet<String>,
    merged: Value,
    identity: Value,
    bytes: usize,
}

impl CompleteCatalog {
    /// The server that listed the catalog.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The number of tools the list names.
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }
}

/// What staging one complete list did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogStage {
    /// The catalog's schema committed, and its tools are accepted.
    Accepted {
        /// The number of accepted tools.
        tools: usize,
    },
    /// The catalog matches the accepted one, so nothing committed.
    Unchanged,
    /// The catalog was refused.
    Rejected {
        /// The failure the refusal records.
        failure: DiscoveryFailure,
        /// The refusal, for an operator.
        reason: String,
    },
}

/// Why a `tools/call` is refused before policy decides it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogRefusal {
    /// The server is not declared.
    Undeclared,
    /// The server has no accepted catalog.
    NotAccepted,
    /// The accepted catalog does not name the tool.
    NotListed,
}

impl fmt::Display for CatalogRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Undeclared => "the MCP server is not declared",
            Self::NotAccepted => "the MCP tool catalog is not accepted",
            Self::NotListed => "the tool is not in the accepted MCP catalog",
        })
    }
}

/// The tool catalogs of every declared MCP server in one box.
pub struct ToolCatalogs {
    policy: Arc<PolicyEngine>,
    inner: Mutex<Catalogs>,
    staging: Mutex<()>,
}

struct Catalogs {
    servers: BTreeMap<String, ServerEntry>,
    lists: BTreeMap<(String, String), PartialList>,
    retained_bytes: usize,
    next_list: u64,
}

struct ServerEntry {
    kind: McpServerKind,
    state: ServerDiscovery,
    accepted: Option<AcceptedCatalog>,
    restages: usize,
}

struct AcceptedCatalog {
    tools: BTreeSet<String>,
    identity: Value,
    bytes: usize,
}

struct PartialList {
    started: u64,
    next_cursor: String,
    seen_cursors: BTreeSet<String>,
    tools: Vec<Value>,
    names: BTreeSet<String>,
    definitions: serde_json::Map<String, Value>,
    pages: usize,
    bytes: usize,
}

impl PartialList {
    fn new(started: u64) -> Self {
        Self {
            started,
            next_cursor: String::new(),
            seen_cursors: BTreeSet::new(),
            tools: Vec::new(),
            names: BTreeSet::new(),
            definitions: serde_json::Map::new(),
            pages: 0,
            bytes: 0,
        }
    }

    fn merge(
        &mut self,
        response: &Value,
        bytes: usize,
    ) -> Result<Option<String>, DiscoveryFailure> {
        self.pages += 1;
        self.bytes = self.bytes.saturating_add(bytes);
        if self.pages > MAXIMUM_LIST_PAGES || self.bytes > MAXIMUM_LIST_BYTES {
            return Err(DiscoveryFailure::CatalogCapture);
        }
        let object = response
            .as_object()
            .ok_or(DiscoveryFailure::CatalogCapture)?;
        if object.contains_key("error") {
            return Err(DiscoveryFailure::CatalogCapture);
        }
        let result = object
            .get("result")
            .and_then(Value::as_object)
            .ok_or(DiscoveryFailure::CatalogCapture)?;
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or(DiscoveryFailure::CatalogCapture)?;
        for tool in tools {
            let name = tool
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or(DiscoveryFailure::CatalogCapture)?;
            if !self.names.insert(name.to_string()) {
                return Err(DiscoveryFailure::CatalogCapture);
            }
            self.tools.push(tool.clone());
        }
        if let Some(definitions) = result.get("$defs") {
            let definitions = definitions
                .as_object()
                .ok_or(DiscoveryFailure::CatalogCapture)?;
            for (name, definition) in definitions {
                match self.definitions.get(name) {
                    Some(previous) if previous != definition => {
                        return Err(DiscoveryFailure::CatalogCapture);
                    }
                    Some(_) => {}
                    None => {
                        self.definitions.insert(name.clone(), definition.clone());
                    }
                }
            }
        }
        match result.get("nextCursor") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(next)) => {
                if !self.seen_cursors.insert(next.clone()) {
                    return Err(DiscoveryFailure::CatalogCapture);
                }
                self.next_cursor.clone_from(next);
                Ok(Some(next.clone()))
            }
            Some(_) => Err(DiscoveryFailure::CatalogCapture),
        }
    }

    fn complete(self, server: &str) -> CompleteCatalog {
        let mut by_name: Vec<&Value> = self.tools.iter().collect();
        by_name.sort_by(|left, right| {
            left.get("name")
                .and_then(Value::as_str)
                .cmp(&right.get("name").and_then(Value::as_str))
        });
        let identity_tools: Vec<Value> = by_name
            .into_iter()
            .map(|tool| {
                serde_json::json!({
                    "name": tool.get("name"),
                    "inputSchema": tool.get("inputSchema"),
                })
            })
            .collect();
        let identity = serde_json::json!({
            "tools": identity_tools,
            "$defs": self.definitions.clone(),
        });
        let mut merged = serde_json::Map::new();
        merged.insert("tools".to_string(), Value::Array(self.tools));
        if !self.definitions.is_empty() {
            merged.insert("$defs".to_string(), Value::Object(self.definitions));
        }
        CompleteCatalog {
            server: server.to_string(),
            tools: self.names,
            merged: serde_json::json!({ "result": merged }),
            identity,
            bytes: self.bytes,
        }
    }
}

impl ToolCatalogs {
    /// Track the declared servers, each `Undiscovered`.
    pub fn new(
        policy: Arc<PolicyEngine>,
        servers: impl IntoIterator<Item = (String, McpServerKind)>,
    ) -> Self {
        Self {
            policy,
            inner: Mutex::new(Catalogs {
                servers: servers
                    .into_iter()
                    .map(|(name, kind)| {
                        (
                            name,
                            ServerEntry {
                                kind,
                                state: ServerDiscovery::Undiscovered,
                                accepted: None,
                                restages: 0,
                            },
                        )
                    })
                    .collect(),
                lists: BTreeMap::new(),
                retained_bytes: 0,
                next_list: 0,
            }),
            staging: Mutex::new(()),
        }
    }

    /// Observe one reply to a client's `tools/list` on `connection`.
    ///
    /// A list is captured only when its first request names no cursor and each later request names
    /// the cursor the previous page returned on the same connection.
    pub fn observe_page(
        &self,
        server: &str,
        connection: &str,
        cursor: Option<&str>,
        response: &Value,
        bytes: usize,
    ) -> Result<ListPage, DiscoveryFailure> {
        let mut inner = self.lock();
        if !inner.servers.contains_key(server) {
            return Ok(ListPage::Ignored);
        }
        let key = (server.to_string(), connection.to_string());
        let mut list = match cursor {
            None => {
                if let Some(abandoned) = inner.lists.remove(&key) {
                    inner.retained_bytes = inner.retained_bytes.saturating_sub(abandoned.bytes);
                }
                let others: Vec<((String, String), u64)> = inner
                    .lists
                    .iter()
                    .filter(|((listed, _), _)| listed == server)
                    .map(|(key, list)| (key.clone(), list.started))
                    .collect();
                if others.len() >= MAXIMUM_CONCURRENT_LISTS
                    && let Some((oldest, _)) =
                        others.into_iter().min_by_key(|(_, started)| *started)
                    && let Some(evicted) = inner.lists.remove(&oldest)
                {
                    inner.retained_bytes = inner.retained_bytes.saturating_sub(evicted.bytes);
                }
                inner.next_list += 1;
                PartialList::new(inner.next_list)
            }
            Some(cursor) => match inner.lists.get(&key) {
                Some(list) if list.next_cursor == cursor => {
                    let list = inner.lists.remove(&key).expect("the list was just found");
                    inner.retained_bytes = inner.retained_bytes.saturating_sub(list.bytes);
                    list
                }
                _ => return Ok(ListPage::Ignored),
            },
        };
        let merged = list.merge(response, bytes);
        let retained = inner.retained_bytes.saturating_add(list.bytes);
        let outcome = match merged {
            Ok(_) if retained > MAXIMUM_RETAINED_BYTES => Err(DiscoveryFailure::RunRetention),
            other => other,
        };
        match outcome {
            Err(failure) => {
                Self::fail_locked(&mut inner, server, failure);
                Err(failure)
            }
            Ok(Some(_)) => {
                inner.retained_bytes = retained;
                inner.lists.insert(key, list);
                Self::begin_listing(&mut inner, server);
                Ok(ListPage::More)
            }
            Ok(None) => {
                Self::begin_listing(&mut inner, server);
                Ok(ListPage::Complete(list.complete(server)))
            }
        }
    }

    /// Stage one complete list's schema, and accept its tools once the schema commits.
    ///
    /// A list equal to the accepted catalog commits nothing. A refused list keeps a stdio server's
    /// accepted catalog.
    pub fn stage(&self, catalog: CompleteCatalog) -> Result<CatalogStage, PolicyStagingError> {
        let _staging = self
            .staging
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let server = catalog.server.clone();
        {
            let mut inner = self.lock();
            let Some(entry) = inner.servers.get_mut(&server) else {
                return Ok(CatalogStage::Rejected {
                    failure: DiscoveryFailure::PolicyStaging,
                    reason: format!("MCP server {server:?} is not declared"),
                });
            };
            if let Some(accepted) = &entry.accepted {
                if accepted.identity == catalog.identity {
                    entry.state = ServerDiscovery::Ready;
                    return Ok(CatalogStage::Unchanged);
                }
                if entry.restages >= MAXIMUM_RESTAGES {
                    entry.state = ServerDiscovery::Ready;
                    return Ok(CatalogStage::Rejected {
                        failure: DiscoveryFailure::PolicyStaging,
                        reason: format!(
                            "MCP server {server:?} changed its catalog more than \
                             {MAXIMUM_RESTAGES} times, so its accepted catalog stays"
                        ),
                    });
                }
            }
        }
        let fragment = match crate::generate_mcp_schema(&server, &catalog.merged.to_string()) {
            Ok(fragment) => fragment,
            Err(error) => {
                return Ok(self.reject(
                    &server,
                    DiscoveryFailure::SchemaGeneration,
                    error.to_string(),
                ));
            }
        };
        let retained = catalog.bytes.saturating_add(fragment.len());
        {
            let inner = self.lock();
            let released = inner
                .servers
                .get(&server)
                .and_then(|entry| entry.accepted.as_ref())
                .map_or(0, |accepted| accepted.bytes);
            if inner
                .retained_bytes
                .saturating_sub(released)
                .saturating_add(retained)
                > MAXIMUM_RETAINED_BYTES
            {
                drop(inner);
                return Ok(self.reject(
                    &server,
                    DiscoveryFailure::RunRetention,
                    "the run discovery retention budget is exhausted".to_string(),
                ));
            }
        }
        // Until the new schema commits, only tools both lists name pass the catalog check.
        let previous = {
            let mut inner = self.lock();
            inner
                .servers
                .get_mut(&server)
                .and_then(|entry| entry.accepted.as_mut())
                .map(|accepted| {
                    let previous = accepted.tools.clone();
                    accepted.tools.retain(|tool| catalog.tools.contains(tool));
                    previous
                })
        };
        let staged = match self.policy.stage_mcp_schema(&server, fragment) {
            Ok(SchemaStage::Accepted { .. }) => Ok(()),
            Ok(SchemaStage::Rejected { reason }) => Err(Ok(reason)),
            Err(error) => Err(Err(error)),
        };
        if staged.is_err()
            && let Some(previous) = previous
            && let Some(accepted) = self
                .lock()
                .servers
                .get_mut(&server)
                .and_then(|entry| entry.accepted.as_mut())
        {
            accepted.tools = previous;
        }
        match staged {
            Ok(()) => {
                let mut inner = self.lock();
                let released = inner
                    .servers
                    .get(&server)
                    .and_then(|entry| entry.accepted.as_ref())
                    .map_or(0, |accepted| accepted.bytes);
                inner.retained_bytes = inner
                    .retained_bytes
                    .saturating_sub(released)
                    .saturating_add(retained);
                let tools = catalog.tools.len();
                let entry = inner
                    .servers
                    .get_mut(&server)
                    .expect("a staged server is declared");
                if entry.accepted.is_some() {
                    entry.restages += 1;
                }
                entry.accepted = Some(AcceptedCatalog {
                    tools: catalog.tools,
                    identity: catalog.identity,
                    bytes: retained,
                });
                entry.state = ServerDiscovery::Ready;
                Ok(CatalogStage::Accepted { tools })
            }
            Err(Ok(reason)) => Ok(self.reject(&server, DiscoveryFailure::PolicyStaging, reason)),
            Err(Err(error)) => Err(error),
        }
    }

    /// Whether a reply to a `tools/list` naming `cursor` on `connection` would be captured.
    pub fn captures(&self, server: &str, connection: &str, cursor: Option<&str>) -> bool {
        let inner = self.lock();
        if !inner.servers.contains_key(server) {
            return false;
        }
        match cursor {
            None => true,
            Some(cursor) => inner
                .lists
                .get(&(server.to_string(), connection.to_string()))
                .is_some_and(|list| list.next_cursor == cursor),
        }
    }

    /// Refuse a `tools/call` unless the server's accepted catalog names `tool` exactly.
    pub fn require_listed(&self, server: &str, tool: &str) -> Result<(), CatalogRefusal> {
        let inner = self.lock();
        let entry = inner
            .servers
            .get(server)
            .ok_or(CatalogRefusal::Undeclared)?;
        match &entry.accepted {
            Some(accepted) if accepted.tools.contains(tool) => Ok(()),
            Some(_) => Err(CatalogRefusal::NotListed),
            None => Err(CatalogRefusal::NotAccepted),
        }
    }

    /// Record that policy refused a server's `tools/list`, so an undiscovered server is terminal.
    pub fn list_denied(&self, server: &str) {
        let mut inner = self.lock();
        if let Some(entry) = inner.servers.get_mut(server)
            && entry.state == ServerDiscovery::Undiscovered
        {
            entry.state = ServerDiscovery::Failed(DiscoveryFailure::ToolsListDenied);
        }
    }

    /// Record that a captured list failed for a reason the server's reply does not show.
    pub fn list_failed(&self, server: &str, connection: &str, failure: DiscoveryFailure) {
        let mut inner = self.lock();
        let key = (server.to_string(), connection.to_string());
        if let Some(list) = inner.lists.remove(&key) {
            inner.retained_bytes = inner.retained_bytes.saturating_sub(list.bytes);
        }
        Self::fail_locked(&mut inner, server, failure);
    }

    /// Drop the unfinished lists of a closed connection.
    pub fn connection_closed(&self, connection: &str) {
        let mut inner = self.lock();
        let closed: Vec<(String, String)> = inner
            .lists
            .keys()
            .filter(|(_, other)| other == connection)
            .cloned()
            .collect();
        for key in closed {
            if let Some(list) = inner.lists.remove(&key) {
                inner.retained_bytes = inner.retained_bytes.saturating_sub(list.bytes);
            }
            let still_listing = inner.lists.keys().any(|(server, _)| *server == key.0);
            if let Some(entry) = inner.servers.get_mut(&key.0)
                && entry.state == ServerDiscovery::Listing
                && !still_listing
            {
                entry.state = if entry.accepted.is_some() {
                    ServerDiscovery::Ready
                } else {
                    ServerDiscovery::Undiscovered
                };
            }
        }
    }

    /// Whether every declared server of `kind` is `Ready` or `Failed`.
    pub fn kind_done(&self, kind: McpServerKind) -> bool {
        self.lock()
            .servers
            .values()
            .filter(|entry| entry.kind == kind)
            .all(|entry| {
                matches!(
                    entry.state,
                    ServerDiscovery::Ready | ServerDiscovery::Failed(_)
                )
            })
    }

    /// Where one server's discovery stands, or `None` for an undeclared server.
    pub fn state(&self, server: &str) -> Option<ServerDiscovery> {
        self.lock().servers.get(server).map(|entry| entry.state)
    }

    fn reject(&self, server: &str, failure: DiscoveryFailure, reason: String) -> CatalogStage {
        let mut inner = self.lock();
        Self::reject_locked(&mut inner, server, failure, reason)
    }

    fn reject_locked(
        inner: &mut Catalogs,
        server: &str,
        failure: DiscoveryFailure,
        reason: String,
    ) -> CatalogStage {
        Self::fail_locked(inner, server, failure);
        CatalogStage::Rejected { failure, reason }
    }

    fn begin_listing(inner: &mut Catalogs, server: &str) {
        if let Some(entry) = inner.servers.get_mut(server)
            && entry.accepted.is_none()
        {
            entry.state = ServerDiscovery::Listing;
        }
    }

    fn fail_locked(inner: &mut Catalogs, server: &str, failure: DiscoveryFailure) {
        let Some(entry) = inner.servers.get_mut(server) else {
            return;
        };
        match entry.kind {
            McpServerKind::Stdio if entry.accepted.is_some() => {
                entry.state = ServerDiscovery::Ready;
            }
            McpServerKind::Stdio => entry.state = ServerDiscovery::Failed(failure),
            McpServerKind::Http => {
                let released = entry.accepted.take().map_or(0, |accepted| accepted.bytes);
                entry.state = ServerDiscovery::Failed(failure);
                inner.retained_bytes = inner.retained_bytes.saturating_sub(released);
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, Catalogs> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl fmt::Debug for ToolCatalogs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolCatalogs")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use super::*;
    use crate::{Operator, Policy};

    struct Fixture {
        catalogs: ToolCatalogs,
        policy: Arc<PolicyEngine>,
        _history: tempfile::TempDir,
    }

    fn fixture(kind: McpServerKind) -> Fixture {
        let history = tempfile::tempdir().expect("history directory");
        let policy = Arc::new(
            PolicyEngine::open_staged(
                &Operator::unanchored(),
                vec![Policy {
                    origin: PathBuf::from("catalog-test.cedar"),
                    text: r#"permit(principal, action == Box::Action::"mcp:call", resource);"#
                        .to_string(),
                }],
                &history.path().join("dogwood.redb"),
            )
            .expect("the staged policy opens"),
        );
        Fixture {
            catalogs: ToolCatalogs::new(Arc::clone(&policy), [("demo".to_string(), kind)]),
            policy,
            _history: history,
        }
    }

    fn page(tools: &[&str], next: Option<&str>) -> Value {
        let tools: Vec<Value> = tools
            .iter()
            .map(|name| {
                json!({
                    "name": name,
                    "description": format!("{name} tool"),
                    "inputSchema": {"type": "object", "properties": {"value": {"type": "string"}}}
                })
            })
            .collect();
        let mut result = json!({ "tools": tools });
        if let Some(next) = next {
            result["nextCursor"] = json!(next);
        }
        json!({"jsonrpc": "2.0", "id": 1, "result": result})
    }

    fn complete(catalogs: &ToolCatalogs, connection: &str, response: &Value) -> CompleteCatalog {
        match catalogs
            .observe_page("demo", connection, None, response, 64)
            .expect("the page is a valid catalog")
        {
            ListPage::Complete(catalog) => catalog,
            other => panic!("one page completes the list: {other:?}"),
        }
    }

    #[test]
    fn a_complete_list_is_accepted_only_after_its_schema_stages() {
        let fixture = fixture(McpServerKind::Stdio);
        let catalog = complete(&fixture.catalogs, "a", &page(&["read"], None));
        assert_eq!(
            fixture.catalogs.require_listed("demo", "read"),
            Err(CatalogRefusal::NotAccepted)
        );
        assert_eq!(
            fixture.catalogs.stage(catalog).expect("staging runs"),
            CatalogStage::Accepted { tools: 1 }
        );
        assert_eq!(fixture.catalogs.require_listed("demo", "read"), Ok(()));
        assert_eq!(
            fixture.catalogs.require_listed("demo", "write"),
            Err(CatalogRefusal::NotListed)
        );
        assert_eq!(fixture.catalogs.state("demo"), Some(ServerDiscovery::Ready));
    }

    #[test]
    fn an_unchanged_list_commits_nothing_even_when_reordered_or_redescribed() {
        let fixture = fixture(McpServerKind::Stdio);
        let first = complete(&fixture.catalogs, "a", &page(&["read", "write"], None));
        fixture
            .catalogs
            .stage(first)
            .expect("the first list stages");
        let mut reordered = page(&["write", "read"], None);
        reordered["result"]["tools"][0]["description"] = json!("changed text");
        let second = complete(&fixture.catalogs, "b", &reordered);
        assert_eq!(
            fixture.catalogs.stage(second).expect("staging runs"),
            CatalogStage::Unchanged
        );
    }

    #[test]
    fn the_newest_changed_list_replaces_the_accepted_catalog() {
        let fixture = fixture(McpServerKind::Stdio);
        let first = complete(&fixture.catalogs, "a", &page(&["read"], None));
        fixture
            .catalogs
            .stage(first)
            .expect("the first list stages");
        let second = complete(&fixture.catalogs, "b", &page(&["write"], None));
        assert_eq!(
            fixture.catalogs.stage(second).expect("staging runs"),
            CatalogStage::Accepted { tools: 1 }
        );
        assert_eq!(fixture.catalogs.require_listed("demo", "write"), Ok(()));
        assert_eq!(
            fixture.catalogs.require_listed("demo", "read"),
            Err(CatalogRefusal::NotListed)
        );
    }

    #[test]
    fn a_failed_relist_keeps_a_stdio_servers_accepted_catalog() {
        let fixture = fixture(McpServerKind::Stdio);
        let first = complete(&fixture.catalogs, "a", &page(&["read"], None));
        fixture
            .catalogs
            .stage(first)
            .expect("the first list stages");
        let broken = json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": "not a list"}});
        assert_eq!(
            fixture
                .catalogs
                .observe_page("demo", "b", None, &broken, 64)
                .expect_err("the page is not a catalog"),
            DiscoveryFailure::CatalogCapture
        );
        assert_eq!(fixture.catalogs.state("demo"), Some(ServerDiscovery::Ready));
        assert_eq!(fixture.catalogs.require_listed("demo", "read"), Ok(()));
    }

    #[test]
    fn a_failed_relist_withdraws_an_http_servers_accepted_catalog() {
        let fixture = fixture(McpServerKind::Http);
        let first = complete(&fixture.catalogs, "", &page(&["read"], None));
        fixture
            .catalogs
            .stage(first)
            .expect("the first list stages");
        let broken = json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": "not a list"}});
        fixture
            .catalogs
            .observe_page("demo", "", None, &broken, 64)
            .expect_err("the page is not a catalog");
        assert_eq!(
            fixture.catalogs.state("demo"),
            Some(ServerDiscovery::Failed(DiscoveryFailure::CatalogCapture))
        );
        assert_eq!(
            fixture.catalogs.require_listed("demo", "read"),
            Err(CatalogRefusal::NotAccepted)
        );
    }

    #[test]
    fn a_list_is_captured_only_along_its_own_cursor_chain() {
        let fixture = fixture(McpServerKind::Stdio);
        assert!(matches!(
            fixture
                .catalogs
                .observe_page("demo", "a", Some("crafted"), &page(&["read"], None), 64),
            Ok(ListPage::Ignored)
        ));
        assert!(matches!(
            fixture
                .catalogs
                .observe_page("demo", "a", None, &page(&["read"], Some("two")), 64),
            Ok(ListPage::More)
        ));
        assert_eq!(
            fixture.catalogs.state("demo"),
            Some(ServerDiscovery::Listing)
        );
        assert!(matches!(
            fixture
                .catalogs
                .observe_page("demo", "b", Some("two"), &page(&["write"], None), 64),
            Ok(ListPage::Ignored)
        ));
        assert!(matches!(
            fixture
                .catalogs
                .observe_page("demo", "a", Some("other"), &page(&["write"], None), 64),
            Ok(ListPage::Ignored)
        ));
        let ListPage::Complete(catalog) = fixture
            .catalogs
            .observe_page("demo", "a", Some("two"), &page(&["write"], None), 64)
            .expect("the chained page is valid")
        else {
            panic!("the chained page completes the list");
        };
        assert_eq!(catalog.tool_count(), 2);
    }

    #[test]
    fn a_repeated_cursor_fails_the_list() {
        let fixture = fixture(McpServerKind::Stdio);
        fixture
            .catalogs
            .observe_page("demo", "a", None, &page(&["read"], Some("loop")), 64)
            .expect("the first page is valid");
        assert_eq!(
            fixture
                .catalogs
                .observe_page(
                    "demo",
                    "a",
                    Some("loop"),
                    &page(&["write"], Some("loop")),
                    64
                )
                .expect_err("a repeated cursor is refused"),
            DiscoveryFailure::CatalogCapture
        );
        assert_eq!(
            fixture.catalogs.state("demo"),
            Some(ServerDiscovery::Failed(DiscoveryFailure::CatalogCapture))
        );
    }

    #[test]
    fn a_list_over_the_page_limit_fails() {
        let fixture = fixture(McpServerKind::Stdio);
        let mut cursor: Option<String> = None;
        for index in 0..MAXIMUM_LIST_PAGES {
            let next = format!("page-{}", index + 1);
            let tool = format!("tool-{index}");
            let page = page(&[tool.as_str()], Some(next.as_str()));
            assert!(matches!(
                fixture
                    .catalogs
                    .observe_page("demo", "a", cursor.as_deref(), &page, 64),
                Ok(ListPage::More)
            ));
            cursor = Some(next);
        }
        assert_eq!(
            fixture
                .catalogs
                .observe_page("demo", "a", cursor.as_deref(), &page(&["last"], None), 64)
                .expect_err("a list over the page limit is refused"),
            DiscoveryFailure::CatalogCapture
        );
    }

    #[test]
    fn a_list_over_the_byte_limit_fails() {
        let fixture = fixture(McpServerKind::Stdio);
        assert_eq!(
            fixture
                .catalogs
                .observe_page(
                    "demo",
                    "a",
                    None,
                    &page(&["read"], None),
                    MAXIMUM_LIST_BYTES + 1
                )
                .expect_err("a list over the byte limit is refused"),
            DiscoveryFailure::CatalogCapture
        );
    }

    #[test]
    fn a_closed_connection_drops_its_unfinished_list() {
        let fixture = fixture(McpServerKind::Stdio);
        fixture
            .catalogs
            .observe_page("demo", "a", None, &page(&["read"], Some("two")), 64)
            .expect("the first page is valid");
        assert!(!fixture.catalogs.kind_done(McpServerKind::Stdio));
        fixture.catalogs.connection_closed("a");
        assert_eq!(
            fixture.catalogs.state("demo"),
            Some(ServerDiscovery::Undiscovered)
        );
        assert!(matches!(
            fixture
                .catalogs
                .observe_page("demo", "a", Some("two"), &page(&["write"], None), 64),
            Ok(ListPage::Ignored)
        ));
    }

    #[test]
    fn a_new_list_past_the_concurrency_bound_evicts_the_oldest_unfinished_one() {
        let fixture = fixture(McpServerKind::Http);
        for connection in ["a", "b", "c", "d", "e"] {
            assert!(matches!(
                fixture.catalogs.observe_page(
                    "demo",
                    connection,
                    None,
                    &page(&["read"], Some("two")),
                    64
                ),
                Ok(ListPage::More)
            ));
        }
        assert!(
            !fixture.catalogs.captures("demo", "a", Some("two")),
            "the oldest unfinished list is evicted"
        );
        assert!(fixture.catalogs.captures("demo", "e", Some("two")));
        assert!(matches!(
            fixture
                .catalogs
                .observe_page("demo", "e", Some("two"), &page(&["write"], None), 64),
            Ok(ListPage::Complete(_))
        ));
    }

    #[test]
    fn only_names_and_input_schemas_decide_whether_a_list_changed() {
        let fixture = fixture(McpServerKind::Stdio);
        let first = complete(&fixture.catalogs, "a", &page(&["read"], None));
        fixture
            .catalogs
            .stage(first)
            .expect("the first list stages");
        let mut decorated = page(&["read"], None);
        decorated["result"]["tools"][0]["annotations"] = json!({"readOnlyHint": true});
        decorated["result"]["tools"][0]["_meta"] = json!({"stamp": "2026-10-06T00:00:00Z"});
        decorated["result"]["tools"][0]["title"] = json!("Read");
        let second = complete(&fixture.catalogs, "b", &decorated);
        assert_eq!(
            fixture.catalogs.stage(second).expect("staging runs"),
            CatalogStage::Unchanged
        );
        let mut retyped = page(&["read"], None);
        retyped["result"]["tools"][0]["inputSchema"]["properties"]["value"]["type"] =
            json!("integer");
        let third = complete(&fixture.catalogs, "c", &retyped);
        assert_eq!(
            fixture.catalogs.stage(third).expect("staging runs"),
            CatalogStage::Accepted { tools: 1 }
        );
    }

    #[test]
    fn unfinished_lists_past_the_run_budget_fail_discovery() {
        let history = tempfile::tempdir().expect("history directory");
        let policy = Arc::new(
            PolicyEngine::open_staged(
                &Operator::unanchored(),
                vec![Policy {
                    origin: PathBuf::from("catalog-test.cedar"),
                    text: r#"permit(principal, action == Box::Action::"mcp:call", resource);"#
                        .to_string(),
                }],
                &history.path().join("dogwood.redb"),
            )
            .expect("the staged policy opens"),
        );
        let servers = ["one", "two", "three", "four", "five"];
        let catalogs = ToolCatalogs::new(
            policy,
            servers
                .iter()
                .map(|server| ((*server).to_string(), McpServerKind::Stdio)),
        );
        for server in &servers[..4] {
            assert!(matches!(
                catalogs.observe_page(
                    server,
                    "a",
                    None,
                    &page(&["read"], Some("two")),
                    MAXIMUM_LIST_BYTES
                ),
                Ok(ListPage::More)
            ));
        }
        assert_eq!(
            catalogs
                .observe_page("five", "a", None, &page(&["read"], Some("two")), 1)
                .expect_err("the run budget is spent"),
            DiscoveryFailure::RunRetention
        );
        assert_eq!(
            catalogs.state("five"),
            Some(ServerDiscovery::Failed(DiscoveryFailure::RunRetention))
        );
        catalogs.connection_closed("a");
        assert!(matches!(
            catalogs.observe_page("five", "b", None, &page(&["read"], None), 1),
            Ok(ListPage::Complete(_))
        ));
    }

    #[test]
    fn changes_past_the_restage_limit_keep_the_accepted_catalog() {
        let fixture = fixture(McpServerKind::Stdio);
        let first = complete(&fixture.catalogs, "a", &page(&["tool-0"], None));
        fixture
            .catalogs
            .stage(first)
            .expect("the first list stages");
        for index in 1..=MAXIMUM_RESTAGES {
            let tool = format!("tool-{index}");
            let catalog = complete(&fixture.catalogs, "a", &page(&[tool.as_str()], None));
            assert_eq!(
                fixture.catalogs.stage(catalog).expect("staging runs"),
                CatalogStage::Accepted { tools: 1 }
            );
        }
        let last = complete(&fixture.catalogs, "a", &page(&["one-too-many"], None));
        assert!(matches!(
            fixture.catalogs.stage(last).expect("staging runs"),
            CatalogStage::Rejected {
                failure: DiscoveryFailure::PolicyStaging,
                ..
            }
        ));
        let kept = format!("tool-{MAXIMUM_RESTAGES}");
        assert_eq!(fixture.catalogs.require_listed("demo", &kept), Ok(()));
    }

    #[test]
    fn changes_past_the_restage_limit_keep_an_http_servers_accepted_catalog() {
        let fixture = fixture(McpServerKind::Http);
        let first = complete(&fixture.catalogs, "", &page(&["tool-0"], None));
        fixture
            .catalogs
            .stage(first)
            .expect("the first list stages");
        for index in 1..=MAXIMUM_RESTAGES + 1 {
            let tool = format!("tool-{index}");
            let catalog = complete(&fixture.catalogs, "", &page(&[tool.as_str()], None));
            fixture.catalogs.stage(catalog).expect("staging runs");
        }
        let kept = format!("tool-{MAXIMUM_RESTAGES}");
        assert_eq!(fixture.catalogs.require_listed("demo", &kept), Ok(()));
        assert_eq!(fixture.catalogs.state("demo"), Some(ServerDiscovery::Ready));
    }

    #[test]
    fn a_denied_list_makes_an_undiscovered_server_terminal() {
        let fixture = fixture(McpServerKind::Http);
        assert!(!fixture.catalogs.kind_done(McpServerKind::Http));
        fixture.catalogs.list_denied("demo");
        assert_eq!(
            fixture.catalogs.state("demo"),
            Some(ServerDiscovery::Failed(DiscoveryFailure::ToolsListDenied))
        );
        assert!(fixture.catalogs.kind_done(McpServerKind::Http));
        assert!(fixture.catalogs.kind_done(McpServerKind::Stdio));
    }

    #[test]
    fn a_staged_catalog_arms_the_policy() {
        let fixture = fixture(McpServerKind::Stdio);
        let catalog = complete(&fixture.catalogs, "a", &page(&["read"], None));
        fixture.catalogs.stage(catalog).expect("the list stages");
        assert!(fixture.policy.finish_mcp_discovery().is_ok());
    }
}
