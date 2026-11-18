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

/// The most times an accepted catalog can change while its source remains retained.
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
    key: Box<CatalogKey>,
    generation: u64,
    tools: BTreeSet<String>,
    merged: Value,
    identity: Value,
    bytes: usize,
}

impl CompleteCatalog {
    /// The server that listed the catalog.
    pub fn server(&self) -> &str {
        &self.key.server
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

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct CatalogKey {
    server: String,
    source: Option<([u8; 32], Option<String>)>,
}

impl fmt::Debug for CatalogKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogKey")
            .field("server", &self.server)
            .field("remote", &self.source.is_some())
            .finish_non_exhaustive()
    }
}

impl CatalogKey {
    fn declared(server: &str) -> Self {
        Self {
            server: server.to_string(),
            source: None,
        }
    }

    #[cfg(feature = "egress-adapter")]
    fn remote(server: &str, source: egress_gateway::McpSource<'_>) -> Self {
        Self {
            server: server.to_string(),
            source: Some((source.endpoint, source.session.map(str::to_string))),
        }
    }
}

struct Catalogs {
    servers: BTreeMap<CatalogKey, ServerEntry>,
    lists: BTreeMap<(CatalogKey, String), PartialList>,
    retained_bytes: usize,
    next_list: u64,
    #[cfg(feature = "egress-adapter")]
    next_generation: u64,
    #[cfg(feature = "egress-adapter")]
    next_use: u64,
}

struct ServerEntry {
    generation: u64,
    #[cfg(feature = "egress-adapter")]
    last_used: u64,
    kind: McpServerKind,
    state: ServerDiscovery,
    accepted: Option<AcceptedCatalog>,
    restages: usize,
}

struct AcceptedCatalog {
    tools: BTreeSet<String>,
    identity: Value,
    bytes: usize,
    #[cfg(feature = "egress-adapter")]
    fragment: Arc<str>,
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

    fn complete(self, key: CatalogKey, generation: u64) -> CompleteCatalog {
        let mut by_name: Vec<&Value> = self.tools.iter().collect();
        by_name.sort_by(|left, right| {
            left.get("name")
                .and_then(Value::as_str)
                .cmp(&right.get("name").and_then(Value::as_str))
        });
        let identity_tools: Vec<Value> = by_name
            .into_iter()
            .map(|tool| {
                let mut identity = serde_json::json!({
                    "name": tool.get("name"),
                    "inputSchema": tool.get("inputSchema"),
                });
                // A server that changes only a tool's outputs restages. Added only when present,
                // so a catalog with no output schemas keeps the identity it had before.
                if let Some(output) = tool.get("outputSchema") {
                    identity["outputSchema"] = output.clone();
                }
                identity
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
            key: Box::new(key),
            generation,
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
                            CatalogKey::declared(&name),
                            ServerEntry {
                                generation: 0,
                                #[cfg(feature = "egress-adapter")]
                                last_used: 0,
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
                #[cfg(feature = "egress-adapter")]
                next_generation: 0,
                #[cfg(feature = "egress-adapter")]
                next_use: 0,
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
        let _staging = self
            .staging
            .lock()
            .map_err(|_| DiscoveryFailure::PolicyStaging)?;
        self.observe_catalog_page(
            CatalogKey::declared(server),
            connection,
            cursor,
            response,
            bytes,
        )
    }

    fn observe_catalog_page(
        &self,
        catalog: CatalogKey,
        connection: &str,
        cursor: Option<&str>,
        response: &Value,
        bytes: usize,
    ) -> Result<ListPage, DiscoveryFailure> {
        let mut inner = self.lock();
        let Some(entry) = inner.servers.get(&catalog) else {
            return Ok(ListPage::Ignored);
        };
        let generation = entry.generation;
        let key = (catalog.clone(), connection.to_string());
        let mut list = match cursor {
            None => {
                if let Some(abandoned) = inner.lists.remove(&key) {
                    inner.retained_bytes = inner.retained_bytes.saturating_sub(abandoned.bytes);
                }
                let others: Vec<((CatalogKey, String), u64)> = inner
                    .lists
                    .iter()
                    .filter(|((listed, _), _)| listed.server == catalog.server)
                    .map(|(key, list)| (key.clone(), list.started))
                    .collect();
                if others.len() >= MAXIMUM_CONCURRENT_LISTS
                    && let Some((oldest, _)) =
                        others.into_iter().min_by_key(|(_, started)| *started)
                    && let Some(evicted) = inner.lists.remove(&oldest)
                {
                    inner.retained_bytes = inner.retained_bytes.saturating_sub(evicted.bytes);
                    let still_listing = inner.lists.keys().any(|(source, _)| *source == oldest.0);
                    if !still_listing
                        && inner
                            .servers
                            .get(&oldest.0)
                            .is_some_and(|entry| entry.accepted.is_none())
                    {
                        Self::fail_locked(&mut inner, &oldest.0, DiscoveryFailure::RunRetention);
                    }
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
        #[cfg(feature = "egress-adapter")]
        let merged = if catalog.source.is_some()
            && merged.is_ok()
            && !Self::reclaim_remote_sources_locked(&mut inner, &catalog, list.bytes, 0, None)
        {
            Err(DiscoveryFailure::RunRetention)
        } else {
            merged
        };
        let retained = inner.retained_bytes.saturating_add(list.bytes);
        let outcome = match merged {
            Ok(_) if retained > MAXIMUM_RETAINED_BYTES => Err(DiscoveryFailure::RunRetention),
            other => other,
        };
        match outcome {
            Err(failure) => {
                Self::fail_locked(&mut inner, &catalog, failure);
                Err(failure)
            }
            Ok(Some(_)) => {
                #[cfg(feature = "egress-adapter")]
                Self::touch_remote_source_locked(&mut inner, &catalog);
                inner.retained_bytes = retained;
                inner.lists.insert(key, list);
                Self::begin_listing(&mut inner, &catalog);
                Ok(ListPage::More)
            }
            Ok(None) => {
                #[cfg(feature = "egress-adapter")]
                Self::touch_remote_source_locked(&mut inner, &catalog);
                Self::begin_listing(&mut inner, &catalog);
                Ok(ListPage::Complete(list.complete(catalog, generation)))
            }
        }
    }

    #[cfg(feature = "egress-adapter")]
    pub(crate) fn observe_remote_page(
        &self,
        server: &str,
        source: egress_gateway::McpSource<'_>,
        cursor: Option<&str>,
        response: &Value,
        bytes: usize,
    ) -> Result<ListPage, DiscoveryFailure> {
        let _staging = self
            .staging
            .lock()
            .map_err(|_| DiscoveryFailure::PolicyStaging)?;
        let key = CatalogKey::remote(server, source);
        if !self.track_remote_source(&key, cursor.is_none())? {
            return Ok(ListPage::Ignored);
        }
        self.observe_catalog_page(
            key,
            source.session.unwrap_or_default(),
            cursor,
            response,
            bytes,
        )
    }

    #[cfg(feature = "egress-adapter")]
    fn track_remote_source(
        &self,
        key: &CatalogKey,
        create: bool,
    ) -> Result<bool, DiscoveryFailure> {
        const MAXIMUM_REMOTE_SOURCES_PER_SERVER: usize = 64;
        let mut inner = self.lock();
        if !inner
            .servers
            .get(&CatalogKey::declared(&key.server))
            .is_some_and(|entry| entry.kind == McpServerKind::Http)
        {
            return Ok(false);
        }
        if inner.servers.contains_key(key) {
            return Ok(true);
        }
        if !create {
            return Ok(false);
        }
        let source_bytes = Self::remote_source_bytes(key);
        if source_bytes > MAXIMUM_RETAINED_BYTES {
            Self::remote_discovery_failed_locked(&mut inner, key, DiscoveryFailure::RunRetention);
            return Err(DiscoveryFailure::RunRetention);
        }
        let Some(generation) = inner.next_generation.checked_add(1) else {
            Self::remote_discovery_failed_locked(&mut inner, key, DiscoveryFailure::RunRetention);
            return Err(DiscoveryFailure::RunRetention);
        };
        if !Self::reclaim_remote_sources_locked(
            &mut inner,
            key,
            source_bytes,
            0,
            Some(MAXIMUM_REMOTE_SOURCES_PER_SERVER),
        ) {
            Self::remote_discovery_failed_locked(&mut inner, key, DiscoveryFailure::RunRetention);
            return Err(DiscoveryFailure::RunRetention);
        }
        inner.next_generation = generation;
        inner.retained_bytes += source_bytes;
        inner.servers.insert(
            key.clone(),
            ServerEntry {
                generation,
                last_used: 0,
                kind: McpServerKind::Http,
                state: ServerDiscovery::Undiscovered,
                accepted: None,
                restages: 0,
            },
        );
        Ok(true)
    }

    #[cfg(feature = "egress-adapter")]
    fn reclaim_remote_sources_locked(
        inner: &mut Catalogs,
        current: &CatalogKey,
        additional: usize,
        released: usize,
        maximum_sources: Option<usize>,
    ) -> bool {
        if additional > MAXIMUM_RETAINED_BYTES {
            return false;
        }
        loop {
            let source_limit = maximum_sources.is_some_and(|maximum| {
                inner
                    .servers
                    .keys()
                    .filter(|key| key.source.is_some() && key.server == current.server)
                    .count()
                    >= maximum
            });
            let byte_limit = inner
                .retained_bytes
                .saturating_sub(released)
                .saturating_add(additional)
                > MAXIMUM_RETAINED_BYTES;
            if !source_limit && !byte_limit {
                return true;
            }
            // Preserve active cursor chains where possible. A completed token can be evicted:
            // its generation prevents it from installing into a later entry for the same source.
            let victim = inner
                .servers
                .iter()
                .filter(|(key, _)| {
                    key.source.is_some()
                        && *key != current
                        && (!source_limit || key.server == current.server)
                })
                .min_by_key(|(key, entry)| {
                    (
                        inner.lists.keys().any(|(listed, _)| listed == *key),
                        entry.accepted.is_some(),
                        entry.last_used,
                    )
                })
                .map(|(key, _)| key.clone());
            let Some(victim) = victim else {
                return false;
            };
            Self::remove_remote_source_locked(inner, &victim);
            Self::remote_discovery_failed_locked(inner, &victim, DiscoveryFailure::RunRetention);
        }
    }

    #[cfg(feature = "egress-adapter")]
    fn remote_source_bytes(key: &CatalogKey) -> usize {
        std::mem::size_of::<CatalogKey>()
            + std::mem::size_of::<ServerEntry>()
            + key.server.len()
            + key
                .source
                .as_ref()
                .map_or(0, |(_, session)| session.as_ref().map_or(0, String::len))
    }

    #[cfg(feature = "egress-adapter")]
    fn touch_remote_source_locked(inner: &mut Catalogs, key: &CatalogKey) {
        if key.source.is_some()
            && let Some(entry) = inner.servers.get_mut(key)
        {
            inner.next_use = inner.next_use.saturating_add(1);
            entry.last_used = inner.next_use;
        }
    }

    #[cfg(feature = "egress-adapter")]
    fn remove_remote_lists_locked(inner: &mut Catalogs, key: &CatalogKey) {
        inner.lists.retain(|(source, _), list| {
            if source == key {
                inner.retained_bytes = inner.retained_bytes.saturating_sub(list.bytes);
                false
            } else {
                true
            }
        });
    }

    #[cfg(feature = "egress-adapter")]
    fn remove_remote_source_locked(inner: &mut Catalogs, key: &CatalogKey) {
        if key.source.is_none() {
            return;
        }
        Self::remove_remote_lists_locked(inner, key);
        if let Some(entry) = inner.servers.remove(key) {
            let released = Self::remote_source_bytes(key)
                .saturating_add(entry.accepted.map_or(0, |accepted| accepted.bytes));
            inner.retained_bytes = inner.retained_bytes.saturating_sub(released);
        }
    }

    #[cfg(feature = "egress-adapter")]
    fn remote_discovery_failed_locked(
        inner: &mut Catalogs,
        key: &CatalogKey,
        failure: DiscoveryFailure,
    ) {
        if let Some(declared) = inner.servers.get_mut(&CatalogKey::declared(&key.server))
            && declared.kind == McpServerKind::Http
            && declared.accepted.is_none()
        {
            declared.state = ServerDiscovery::Failed(failure);
        }
    }

    #[cfg(feature = "egress-adapter")]
    pub(crate) fn remote_list_denied(&self, server: &str, source: egress_gateway::McpSource<'_>) {
        let Ok(_staging) = self.staging.lock() else {
            return;
        };
        let key = CatalogKey::remote(server, source);
        let mut inner = self.lock();
        if inner
            .servers
            .get(&key)
            .is_some_and(|entry| entry.accepted.is_some())
        {
            // A denied refresh does not invalidate the last accepted catalog, but its cursor
            // chain can no longer complete and must not retain discovery bytes.
            Self::remove_remote_lists_locked(&mut inner, &key);
        } else {
            Self::fail_locked(&mut inner, &key, DiscoveryFailure::ToolsListDenied);
        }
    }

    #[cfg(feature = "egress-adapter")]
    pub(crate) fn remote_list_failed(
        &self,
        server: &str,
        source: egress_gateway::McpSource<'_>,
        failure: DiscoveryFailure,
    ) {
        let Ok(_staging) = self.staging.lock() else {
            return;
        };
        let mut inner = self.lock();
        Self::fail_locked(&mut inner, &CatalogKey::remote(server, source), failure);
    }

    #[cfg(feature = "egress-adapter")]
    pub(crate) fn refine_remote_tool_call(
        &self,
        governed: &crate::GovernedBox,
        principal: &crate::Principal,
        server: &str,
        source: egress_gateway::McpSource<'_>,
        tool: &str,
        arguments: &Value,
    ) -> Result<(crate::Decision, Option<crate::PendingToolResponse>), CatalogRefusal> {
        let Ok(_staging) = self.staging.lock() else {
            return Ok((crate::Decision::internal_fault(), None));
        };
        let fragment = {
            let mut inner = self.lock();
            if !inner.servers.contains_key(&CatalogKey::declared(server)) {
                return Err(CatalogRefusal::Undeclared);
            }
            let entry = inner
                .servers
                .get(&CatalogKey::remote(server, source))
                .ok_or(CatalogRefusal::NotAccepted)?;
            let accepted = entry.accepted.as_ref().ok_or(CatalogRefusal::NotAccepted)?;
            if !accepted.tools.contains(tool) {
                return Err(CatalogRefusal::NotListed);
            }
            let fragment = Arc::clone(&accepted.fragment);
            Self::touch_remote_source_locked(&mut inner, &CatalogKey::remote(server, source));
            fragment
        };
        Ok(self
            .policy
            .refine_tool_call_with_schema(governed, principal, server, tool, arguments, &fragment))
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
        let key = *catalog.key;
        let server = &key.server;
        {
            let mut inner = self.lock();
            let Some(entry) = inner.servers.get_mut(&key) else {
                let reason = if key.source.is_some()
                    && inner.servers.contains_key(&CatalogKey::declared(server))
                {
                    format!("MCP server {server:?} catalog is no longer cached; list tools again")
                } else {
                    format!("MCP server {server:?} is not declared")
                };
                return Ok(CatalogStage::Rejected {
                    failure: DiscoveryFailure::PolicyStaging,
                    reason,
                });
            };
            if entry.generation != catalog.generation {
                return Ok(CatalogStage::Rejected {
                    failure: DiscoveryFailure::CatalogCapture,
                    reason: format!("MCP server {server:?} catalog belongs to an evicted source"),
                });
            }
            if let Some(accepted) = &entry.accepted {
                if accepted.identity == catalog.identity {
                    entry.state = ServerDiscovery::Ready;
                    #[cfg(feature = "egress-adapter")]
                    Self::touch_remote_source_locked(&mut inner, &key);
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
        let fragment = match crate::generate_mcp_schema(server, &catalog.merged.to_string()) {
            Ok(fragment) => fragment,
            Err(error) => {
                return Ok(self.reject(
                    &key,
                    DiscoveryFailure::SchemaGeneration,
                    error.to_string(),
                ));
            }
        };
        let retained = catalog.bytes.saturating_add(fragment.len());
        {
            #[allow(unused_mut)]
            let mut inner = self.lock();
            let released = inner
                .servers
                .get(&key)
                .and_then(|entry| entry.accepted.as_ref())
                .map_or(0, |accepted| accepted.bytes);
            #[cfg(feature = "egress-adapter")]
            if key.source.is_some() {
                Self::reclaim_remote_sources_locked(&mut inner, &key, retained, released, None);
            }
            if inner
                .retained_bytes
                .saturating_sub(released)
                .saturating_add(retained)
                > MAXIMUM_RETAINED_BYTES
            {
                drop(inner);
                return Ok(self.reject(
                    &key,
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
                .get_mut(&key)
                .and_then(|entry| entry.accepted.as_mut())
                .map(|accepted| {
                    let previous = accepted.tools.clone();
                    accepted.tools.retain(|tool| catalog.tools.contains(tool));
                    previous
                })
        };
        let staged = match self.policy.stage_mcp_schema(server, fragment.clone()) {
            Ok(SchemaStage::Accepted { .. }) => Ok(()),
            Ok(SchemaStage::Rejected { reason }) => Err(Ok(reason)),
            Err(error) => Err(Err(error)),
        };
        if staged.is_err()
            && let Some(previous) = previous
            && let Some(accepted) = self
                .lock()
                .servers
                .get_mut(&key)
                .and_then(|entry| entry.accepted.as_mut())
        {
            accepted.tools = previous;
        }
        match staged {
            Ok(()) => {
                let mut inner = self.lock();
                let released = inner
                    .servers
                    .get(&key)
                    .and_then(|entry| entry.accepted.as_ref())
                    .map_or(0, |accepted| accepted.bytes);
                inner.retained_bytes = inner
                    .retained_bytes
                    .saturating_sub(released)
                    .saturating_add(retained);
                let tools = catalog.tools.len();
                let entry = inner
                    .servers
                    .get_mut(&key)
                    .expect("a staged server is declared");
                if entry.accepted.is_some() {
                    entry.restages += 1;
                }
                entry.accepted = Some(AcceptedCatalog {
                    tools: catalog.tools,
                    identity: catalog.identity,
                    bytes: retained,
                    #[cfg(feature = "egress-adapter")]
                    fragment: Arc::from(fragment),
                });
                entry.state = ServerDiscovery::Ready;
                #[cfg(feature = "egress-adapter")]
                Self::touch_remote_source_locked(&mut inner, &key);
                Ok(CatalogStage::Accepted { tools })
            }
            Err(Ok(reason)) => Ok(self.reject(&key, DiscoveryFailure::PolicyStaging, reason)),
            Err(Err(error)) => Err(error),
        }
    }

    /// Whether a reply to a `tools/list` naming `cursor` on `connection` would be captured.
    pub fn captures(&self, server: &str, connection: &str, cursor: Option<&str>) -> bool {
        let inner = self.lock();
        let server = CatalogKey::declared(server);
        if !inner.servers.contains_key(&server) {
            return false;
        }
        match cursor {
            None => true,
            Some(cursor) => inner
                .lists
                .get(&(server, connection.to_string()))
                .is_some_and(|list| list.next_cursor == cursor),
        }
    }

    /// Refuse a `tools/call` unless the server's accepted catalog names `tool` exactly.
    pub fn require_listed(&self, server: &str, tool: &str) -> Result<(), CatalogRefusal> {
        let inner = self.lock();
        let entry = inner
            .servers
            .get(&CatalogKey::declared(server))
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
        if let Some(entry) = inner.servers.get_mut(&CatalogKey::declared(server))
            && entry.state == ServerDiscovery::Undiscovered
        {
            entry.state = ServerDiscovery::Failed(DiscoveryFailure::ToolsListDenied);
        }
    }

    /// Record that a captured list failed for a reason the server's reply does not show.
    pub fn list_failed(&self, server: &str, connection: &str, failure: DiscoveryFailure) {
        let mut inner = self.lock();
        let key = (CatalogKey::declared(server), connection.to_string());
        if let Some(list) = inner.lists.remove(&key) {
            inner.retained_bytes = inner.retained_bytes.saturating_sub(list.bytes);
        }
        Self::fail_locked(&mut inner, &key.0, failure);
    }

    /// Drop the unfinished lists of a closed connection.
    pub fn connection_closed(&self, connection: &str) {
        let mut inner = self.lock();
        let closed: Vec<(CatalogKey, String)> = inner
            .lists
            .keys()
            .filter(|(key, other)| key.source.is_none() && other == connection)
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
        let inner = self.lock();
        inner
            .servers
            .iter()
            .filter(|(key, entry)| key.source.is_none() && entry.kind == kind)
            .all(|(key, _)| {
                matches!(
                    Self::server_state(&inner, &key.server),
                    Some(ServerDiscovery::Ready | ServerDiscovery::Failed(_))
                )
            })
    }

    /// Where one server's discovery stands, or `None` for an undeclared server.
    pub fn state(&self, server: &str) -> Option<ServerDiscovery> {
        Self::server_state(&self.lock(), server)
    }

    fn server_state(inner: &Catalogs, server: &str) -> Option<ServerDiscovery> {
        let declared = inner.servers.get(&CatalogKey::declared(server))?;
        let mut state = declared.state;
        for (_, entry) in inner.servers.iter().filter(|(key, _)| key.server == server) {
            match entry.state {
                ServerDiscovery::Ready => return Some(ServerDiscovery::Ready),
                ServerDiscovery::Failed(_) if state != ServerDiscovery::Listing => {
                    state = entry.state
                }
                ServerDiscovery::Listing => state = ServerDiscovery::Listing,
                _ => {}
            }
        }
        Some(state)
    }

    fn reject(
        &self,
        server: &CatalogKey,
        failure: DiscoveryFailure,
        reason: String,
    ) -> CatalogStage {
        let mut inner = self.lock();
        Self::reject_locked(&mut inner, server, failure, reason)
    }

    fn reject_locked(
        inner: &mut Catalogs,
        server: &CatalogKey,
        failure: DiscoveryFailure,
        reason: String,
    ) -> CatalogStage {
        Self::fail_locked(inner, server, failure);
        CatalogStage::Rejected { failure, reason }
    }

    fn begin_listing(inner: &mut Catalogs, server: &CatalogKey) {
        if let Some(entry) = inner.servers.get_mut(server)
            && entry.accepted.is_none()
        {
            entry.state = ServerDiscovery::Listing;
        }
    }

    fn fail_locked(inner: &mut Catalogs, server: &CatalogKey, failure: DiscoveryFailure) {
        #[cfg(feature = "egress-adapter")]
        if server.source.is_some() {
            Self::remove_remote_source_locked(inner, server);
            Self::remote_discovery_failed_locked(inner, server, failure);
            return;
        }
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
    fn a_list_that_changes_only_an_output_schema_restages() {
        let fixture = fixture(McpServerKind::Stdio);
        let first = complete(&fixture.catalogs, "a", &page(&["read"], None));
        fixture
            .catalogs
            .stage(first)
            .expect("the first list stages");
        let mut with_output = page(&["read"], None);
        with_output["result"]["tools"][0]["outputSchema"] = json!({
            "type": "object",
            "properties": {"verified": {"type": "boolean"}},
            "required": ["verified"]
        });
        let second = complete(&fixture.catalogs, "b", &with_output);
        assert_eq!(
            fixture.catalogs.stage(second).expect("staging runs"),
            CatalogStage::Accepted { tools: 1 }
        );
        let mut retyped = with_output.clone();
        retyped["result"]["tools"][0]["outputSchema"]["properties"]["verified"]["type"] =
            json!("string");
        let third = complete(&fixture.catalogs, "c", &retyped);
        assert_eq!(
            fixture.catalogs.stage(third).expect("staging runs"),
            CatalogStage::Accepted { tools: 1 }
        );
        let fourth = complete(&fixture.catalogs, "d", &retyped);
        assert_eq!(
            fixture.catalogs.stage(fourth).expect("staging runs"),
            CatalogStage::Unchanged
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

    /// An http server whose list missed its deadline still stages a later list, on any session.
    #[test]
    fn an_http_list_after_a_capture_failure_stages_on_a_later_session() {
        let fixture = fixture(McpServerKind::Http);
        fixture
            .catalogs
            .list_failed("demo", "first", DiscoveryFailure::CaptureDeadline);
        assert_eq!(
            fixture.catalogs.state("demo"),
            Some(ServerDiscovery::Failed(DiscoveryFailure::CaptureDeadline))
        );
        assert_eq!(
            fixture.catalogs.require_listed("demo", "read"),
            Err(CatalogRefusal::NotAccepted)
        );

        let page = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
            {"name": "read", "inputSchema": {"type": "object",
             "properties": {"path": {"type": "string"}}}}
        ]}});
        let ListPage::Complete(complete) = fixture
            .catalogs
            .observe_page("demo", "second", None, &page, 65536)
            .expect("the later page is a catalog")
        else {
            panic!("the later page must complete a list");
        };
        assert!(matches!(
            fixture.catalogs.stage(complete),
            Ok(CatalogStage::Accepted { .. })
        ));
        assert_eq!(fixture.catalogs.state("demo"), Some(ServerDiscovery::Ready));
        assert_eq!(fixture.catalogs.require_listed("demo", "read"), Ok(()));
    }

    #[cfg(feature = "egress-adapter")]
    #[test]
    fn evicted_remote_pages_do_not_leave_discovery_pending() {
        let fixture = fixture(McpServerKind::Http);
        for index in 0..=MAXIMUM_CONCURRENT_LISTS {
            let source = egress_gateway::McpSource {
                endpoint: [index as u8; 32],
                session: None,
            };
            assert!(matches!(
                fixture.catalogs.observe_remote_page(
                    "demo",
                    source,
                    None,
                    &page(&["read"], Some("next")),
                    100
                ),
                Ok(ListPage::More)
            ));
        }
        let evicted = CatalogKey::remote(
            "demo",
            egress_gateway::McpSource {
                endpoint: [0; 32],
                session: None,
            },
        );
        assert!(!fixture.catalogs.lock().servers.contains_key(&evicted));
        assert_remote_retention(&fixture.catalogs);
        for index in 1..=MAXIMUM_CONCURRENT_LISTS {
            fixture.catalogs.remote_list_failed(
                "demo",
                egress_gateway::McpSource {
                    endpoint: [index as u8; 32],
                    session: None,
                },
                DiscoveryFailure::CatalogCapture,
            );
        }
        assert!(fixture.catalogs.kind_done(McpServerKind::Http));
    }

    #[cfg(feature = "egress-adapter")]
    #[test]
    fn remote_sources_recover_after_sequential_session_turnover() {
        let fixture = fixture(McpServerKind::Http);
        for index in 0..65 {
            let session = format!("session-{index}");
            let source = egress_gateway::McpSource {
                endpoint: [0; 32],
                session: Some(&session),
            };
            let ListPage::Complete(catalog) = fixture
                .catalogs
                .observe_remote_page("demo", source, None, &page(&["read"], None), 100)
                .expect("a new session can list after earlier sessions finish")
            else {
                panic!("one page completes a session's catalog");
            };
            assert!(matches!(
                fixture.catalogs.stage(catalog),
                Ok(CatalogStage::Accepted { .. } | CatalogStage::Unchanged)
            ));
        }
    }

    #[cfg(feature = "egress-adapter")]
    #[test]
    fn remote_sources_recover_after_unknown_denied_lists() {
        let fixture = fixture(McpServerKind::Http);
        for index in 0..64 {
            fixture.catalogs.remote_list_denied(
                "demo",
                egress_gateway::McpSource {
                    endpoint: [index; 32],
                    session: None,
                },
            );
        }
        assert!(fixture.catalogs.kind_done(McpServerKind::Http));
        assert_eq!(fixture.catalogs.lock().servers.len(), 1);
        assert_eq!(fixture.catalogs.lock().retained_bytes, 0);
        let ListPage::Complete(catalog) = fixture
            .catalogs
            .observe_remote_page(
                "demo",
                egress_gateway::McpSource {
                    endpoint: [64; 32],
                    session: None,
                },
                None,
                &page(&["read"], None),
                100,
            )
            .expect("denied lists do not prevent a new source from discovering")
        else {
            panic!("one page completes the catalog");
        };
        assert!(matches!(
            fixture.catalogs.stage(catalog),
            Ok(CatalogStage::Accepted { .. })
        ));
    }

    #[cfg(feature = "egress-adapter")]
    #[test]
    fn remote_sources_recover_after_unknown_failed_lists() {
        let fixture = fixture(McpServerKind::Http);
        for index in 0..64 {
            fixture.catalogs.remote_list_failed(
                "demo",
                egress_gateway::McpSource {
                    endpoint: [index; 32],
                    session: None,
                },
                DiscoveryFailure::CatalogCapture,
            );
        }
        assert!(fixture.catalogs.kind_done(McpServerKind::Http));
        assert_eq!(fixture.catalogs.lock().servers.len(), 1);
        assert_eq!(fixture.catalogs.lock().retained_bytes, 0);
        let ListPage::Complete(catalog) = fixture
            .catalogs
            .observe_remote_page(
                "demo",
                egress_gateway::McpSource {
                    endpoint: [64; 32],
                    session: None,
                },
                None,
                &page(&["read"], None),
                100,
            )
            .expect("failed lists do not prevent a new source from discovering")
        else {
            panic!("one page completes the catalog");
        };
        assert!(matches!(
            fixture.catalogs.stage(catalog),
            Ok(CatalogStage::Accepted { .. })
        ));
    }

    #[cfg(feature = "egress-adapter")]
    fn complete_remote(
        catalogs: &ToolCatalogs,
        server: &str,
        source: egress_gateway::McpSource<'_>,
        response: &Value,
        bytes: usize,
    ) -> CompleteCatalog {
        match catalogs
            .observe_remote_page(server, source, None, response, bytes)
            .expect("the remote page can be captured")
        {
            ListPage::Complete(catalog) => catalog,
            other => panic!("one page completes the remote catalog: {other:?}"),
        }
    }

    #[cfg(feature = "egress-adapter")]
    fn assert_remote_retention(catalogs: &ToolCatalogs) {
        let inner = catalogs.lock();
        let metadata: usize = inner
            .servers
            .keys()
            .filter(|key| key.source.is_some())
            .map(ToolCatalogs::remote_source_bytes)
            .sum();
        let accepted: usize = inner
            .servers
            .values()
            .filter_map(|entry| entry.accepted.as_ref())
            .map(|catalog| catalog.bytes)
            .sum();
        let pages: usize = inner.lists.values().map(|list| list.bytes).sum();
        assert_eq!(inner.retained_bytes, metadata + accepted + pages);
        assert!(inner.retained_bytes <= MAXIMUM_RETAINED_BYTES);
    }

    #[cfg(feature = "egress-adapter")]
    #[test]
    fn remote_source_reclamation_preserves_bounded_cursor_chains() {
        let fixture = fixture(McpServerKind::Http);
        for index in 0..64 {
            let source = egress_gateway::McpSource {
                endpoint: [index; 32],
                session: None,
            };
            assert!(matches!(
                fixture.catalogs.observe_remote_page(
                    "demo",
                    source,
                    None,
                    &page(&["read"], Some("next")),
                    100
                ),
                Ok(ListPage::More)
            ));
            assert_remote_retention(&fixture.catalogs);
            let inner = fixture.catalogs.lock();
            assert!(inner.lists.len() <= MAXIMUM_CONCURRENT_LISTS);
            assert!(inner.servers.len() <= MAXIMUM_CONCURRENT_LISTS + 1);
        }
        assert!(!fixture.catalogs.kind_done(McpServerKind::Http));
        let evicted = egress_gateway::McpSource {
            endpoint: [0; 32],
            session: None,
        };
        assert!(matches!(
            fixture.catalogs.observe_remote_page(
                "demo",
                evicted,
                Some("next"),
                &page(&["old-tail"], None),
                100
            ),
            Ok(ListPage::Ignored)
        ));
        let catalog = complete_remote(
            &fixture.catalogs,
            "demo",
            evicted,
            &page(&["new"], None),
            100,
        );
        assert!(matches!(
            fixture.catalogs.stage(catalog),
            Ok(CatalogStage::Accepted { .. })
        ));
        assert_eq!(fixture.catalogs.state("demo"), Some(ServerDiscovery::Ready));
        assert_remote_retention(&fixture.catalogs);
    }

    #[cfg(feature = "egress-adapter")]
    #[test]
    fn a_completed_remote_catalog_cannot_replace_a_recreated_source() {
        let fixture = fixture(McpServerKind::Http);
        let source = egress_gateway::McpSource {
            endpoint: [0; 32],
            session: Some("reused-session"),
        };
        let uncached = complete_remote(
            &fixture.catalogs,
            "demo",
            source,
            &page(&["old"], None),
            100,
        );
        let stale = complete_remote(
            &fixture.catalogs,
            "demo",
            source,
            &page(&["old"], None),
            100,
        );
        for index in 1..=64 {
            let catalog = complete_remote(
                &fixture.catalogs,
                "demo",
                egress_gateway::McpSource {
                    endpoint: [index; 32],
                    session: None,
                },
                &page(&["other"], None),
                100,
            );
            assert!(matches!(
                fixture.catalogs.stage(catalog),
                Ok(CatalogStage::Accepted { .. })
            ));
        }
        let key = CatalogKey::remote("demo", source);
        assert!(!fixture.catalogs.lock().servers.contains_key(&key));
        let retained_before_rejection = fixture.catalogs.lock().retained_bytes;
        assert_eq!(
            fixture
                .catalogs
                .stage(uncached)
                .expect("an uncached catalog is rejected"),
            CatalogStage::Rejected {
                failure: DiscoveryFailure::PolicyStaging,
                reason: "MCP server \"demo\" catalog is no longer cached; list tools again"
                    .to_string(),
            }
        );
        let inner = fixture.catalogs.lock();
        assert!(inner.servers.contains_key(&CatalogKey::declared("demo")));
        assert!(!inner.servers.contains_key(&key));
        assert_eq!(inner.retained_bytes, retained_before_rejection);
        drop(inner);
        assert_remote_retention(&fixture.catalogs);
        let replacement = complete_remote(
            &fixture.catalogs,
            "demo",
            source,
            &page(&["new"], None),
            100,
        );
        assert!(matches!(
            fixture.catalogs.stage(replacement),
            Ok(CatalogStage::Accepted { .. })
        ));
        let retained = fixture.catalogs.lock().retained_bytes;
        assert!(matches!(
            fixture.catalogs.stage(stale),
            Ok(CatalogStage::Rejected {
                failure: DiscoveryFailure::CatalogCapture,
                ..
            })
        ));
        let inner = fixture.catalogs.lock();
        let accepted = inner.servers[&key]
            .accepted
            .as_ref()
            .expect("replacement remains accepted");
        assert!(accepted.tools.contains("new"));
        assert!(!accepted.tools.contains("old"));
        assert_eq!(inner.retained_bytes, retained);
        drop(inner);
        assert_remote_retention(&fixture.catalogs);
    }

    #[cfg(feature = "egress-adapter")]
    #[test]
    fn remote_eviction_preserves_a_cursor_chain_when_an_idle_catalog_can_leave() {
        let fixture = fixture(McpServerKind::Http);
        let source = egress_gateway::McpSource {
            endpoint: [0; 32],
            session: None,
        };
        assert!(matches!(
            fixture.catalogs.observe_remote_page(
                "demo",
                source,
                None,
                &page(&["head"], Some("next")),
                100
            ),
            Ok(ListPage::More)
        ));
        for index in 1..=64 {
            let catalog = complete_remote(
                &fixture.catalogs,
                "demo",
                egress_gateway::McpSource {
                    endpoint: [index; 32],
                    session: None,
                },
                &page(&["other"], None),
                100,
            );
            assert!(matches!(
                fixture.catalogs.stage(catalog),
                Ok(CatalogStage::Accepted { .. })
            ));
        }
        let ListPage::Complete(catalog) = fixture
            .catalogs
            .observe_remote_page("demo", source, Some("next"), &page(&["tail"], None), 100)
            .expect("the protected cursor chain continues")
        else {
            panic!("the last page completes the protected chain");
        };
        assert!(matches!(
            fixture.catalogs.stage(catalog),
            Ok(CatalogStage::Accepted { .. })
        ));
        let inner = fixture.catalogs.lock();
        let accepted = inner.servers[&CatalogKey::remote("demo", source)]
            .accepted
            .as_ref()
            .unwrap();
        assert!(accepted.tools.contains("head") && accepted.tools.contains("tail"));
        assert_eq!(inner.servers.len(), 65);
        drop(inner);
        assert_remote_retention(&fixture.catalogs);
    }

    #[cfg(feature = "egress-adapter")]
    #[test]
    fn a_failed_remote_refresh_releases_metadata_catalog_and_pages() {
        let fixture = fixture(McpServerKind::Http);
        let source = egress_gateway::McpSource {
            endpoint: [0; 32],
            session: Some("session"),
        };
        let catalog = complete_remote(
            &fixture.catalogs,
            "demo",
            source,
            &page(&["read"], None),
            100,
        );
        assert!(matches!(
            fixture.catalogs.stage(catalog),
            Ok(CatalogStage::Accepted { .. })
        ));
        assert!(matches!(
            fixture.catalogs.observe_remote_page(
                "demo",
                source,
                None,
                &page(&["replacement"], Some("next")),
                200
            ),
            Ok(ListPage::More)
        ));
        assert_remote_retention(&fixture.catalogs);
        fixture
            .catalogs
            .remote_list_failed("demo", source, DiscoveryFailure::CatalogCapture);
        let inner = fixture.catalogs.lock();
        assert_eq!(inner.servers.len(), 1);
        assert!(inner.lists.is_empty());
        assert_eq!(inner.retained_bytes, 0);
        drop(inner);
        assert!(fixture.catalogs.kind_done(McpServerKind::Http));
        assert_remote_retention(&fixture.catalogs);
    }

    #[cfg(feature = "egress-adapter")]
    #[test]
    fn a_denied_remote_refresh_releases_pages_and_keeps_the_accepted_catalog() {
        let fixture = fixture(McpServerKind::Http);
        let source = egress_gateway::McpSource {
            endpoint: [0; 32],
            session: Some("session"),
        };
        let catalog = complete_remote(
            &fixture.catalogs,
            "demo",
            source,
            &page(&["read"], None),
            100,
        );
        assert!(matches!(
            fixture.catalogs.stage(catalog),
            Ok(CatalogStage::Accepted { .. })
        ));
        let retained = fixture.catalogs.lock().retained_bytes;
        assert!(matches!(
            fixture.catalogs.observe_remote_page(
                "demo",
                source,
                None,
                &page(&["replacement"], Some("next")),
                200
            ),
            Ok(ListPage::More)
        ));
        fixture.catalogs.remote_list_denied("demo", source);
        let inner = fixture.catalogs.lock();
        assert!(inner.lists.is_empty());
        assert_eq!(inner.retained_bytes, retained);
        let accepted = inner.servers[&CatalogKey::remote("demo", source)]
            .accepted
            .as_ref()
            .unwrap();
        assert!(accepted.tools.contains("read"));
        assert!(!accepted.tools.contains("replacement"));
        drop(inner);
        assert_remote_retention(&fixture.catalogs);
    }

    #[cfg(feature = "egress-adapter")]
    fn fill_remote_retention(catalogs: &ToolCatalogs) -> egress_gateway::McpSource<'static> {
        // The trusted capture-byte parameter exercises the budget without large test allocations.
        for index in 0..3 {
            let catalog = complete_remote(
                catalogs,
                "demo",
                egress_gateway::McpSource {
                    endpoint: [index; 32],
                    session: None,
                },
                &page(&["read"], None),
                MAXIMUM_LIST_BYTES,
            );
            assert!(matches!(
                catalogs.stage(catalog),
                Ok(CatalogStage::Accepted { .. })
            ));
        }
        let last = egress_gateway::McpSource {
            endpoint: [3; 32],
            session: None,
        };
        let bytes = {
            let inner = catalogs.lock();
            let accepted = inner
                .servers
                .values()
                .find_map(|entry| entry.accepted.as_ref())
                .unwrap();
            let fragment_bytes = accepted.bytes - MAXIMUM_LIST_BYTES;
            MAXIMUM_RETAINED_BYTES
                - inner.retained_bytes
                - ToolCatalogs::remote_source_bytes(&CatalogKey::remote("demo", last))
                - fragment_bytes
        };
        assert!(bytes <= MAXIMUM_LIST_BYTES);
        let catalog = complete_remote(catalogs, "demo", last, &page(&["read"], None), bytes);
        assert!(matches!(
            catalogs.stage(catalog),
            Ok(CatalogStage::Accepted { .. })
        ));
        assert_eq!(catalogs.lock().retained_bytes, MAXIMUM_RETAINED_BYTES);
        assert_remote_retention(catalogs);
        last
    }

    #[cfg(feature = "egress-adapter")]
    #[test]
    fn remote_metadata_byte_pressure_reclaims_catalogs_from_other_servers() {
        let mut fixture = fixture(McpServerKind::Http);
        fixture.catalogs = ToolCatalogs::new(
            Arc::clone(&fixture.policy),
            [
                ("demo".to_string(), McpServerKind::Http),
                ("other".to_string(), McpServerKind::Http),
            ],
        );
        let last = fill_remote_retention(&fixture.catalogs);
        let catalog = complete_remote(
            &fixture.catalogs,
            "other",
            last,
            &page(&["read"], None),
            100,
        );
        assert!(matches!(
            fixture.catalogs.stage(catalog),
            Ok(CatalogStage::Accepted { .. })
        ));
        let inner = fixture.catalogs.lock();
        assert!(!inner.servers.contains_key(&CatalogKey::remote(
            "demo",
            egress_gateway::McpSource {
                endpoint: [0; 32],
                session: None,
            }
        )));
        assert!(
            inner.servers[&CatalogKey::remote("other", last)]
                .accepted
                .is_some()
        );
        assert!(inner.servers.contains_key(&CatalogKey::declared("demo")));
        assert!(inner.servers.contains_key(&CatalogKey::declared("other")));
        drop(inner);
        assert_remote_retention(&fixture.catalogs);
    }

    #[cfg(feature = "egress-adapter")]
    #[test]
    fn remote_page_byte_pressure_preserves_the_source_being_refreshed() {
        let fixture = fixture(McpServerKind::Http);
        fill_remote_retention(&fixture.catalogs);
        let current = egress_gateway::McpSource {
            endpoint: [0; 32],
            session: None,
        };
        let evicted = egress_gateway::McpSource {
            endpoint: [1; 32],
            session: None,
        };
        assert!(matches!(
            fixture.catalogs.observe_remote_page(
                "demo",
                current,
                None,
                &page(&["updated"], Some("next")),
                128
            ),
            Ok(ListPage::More)
        ));
        let inner = fixture.catalogs.lock();
        assert!(
            inner.servers[&CatalogKey::remote("demo", current)]
                .accepted
                .is_some()
        );
        assert!(
            !inner
                .servers
                .contains_key(&CatalogKey::remote("demo", evicted))
        );
        drop(inner);
        assert_remote_retention(&fixture.catalogs);
        let ListPage::Complete(catalog) = fixture
            .catalogs
            .observe_remote_page("demo", current, Some("next"), &page(&["tail"], None), 128)
            .expect("the refresh still owns its cursor chain")
        else {
            panic!("the refresh completes");
        };
        assert!(matches!(
            fixture.catalogs.stage(catalog),
            Ok(CatalogStage::Accepted { .. })
        ));
        let inner = fixture.catalogs.lock();
        let accepted = inner.servers[&CatalogKey::remote("demo", current)]
            .accepted
            .as_ref()
            .unwrap();
        assert!(accepted.tools.contains("updated") && accepted.tools.contains("tail"));
        assert!(!accepted.tools.contains("read"));
        drop(inner);
        assert_remote_retention(&fixture.catalogs);
    }

    #[cfg(feature = "egress-adapter")]
    #[test]
    fn remote_schema_byte_pressure_reclaims_another_source() {
        let fixture = fixture(McpServerKind::Http);
        let released = fill_remote_retention(&fixture.catalogs);
        fixture
            .catalogs
            .remote_list_failed("demo", released, DiscoveryFailure::CatalogCapture);
        let current = egress_gateway::McpSource {
            endpoint: [4; 32],
            session: None,
        };
        let oldest = egress_gateway::McpSource {
            endpoint: [0; 32],
            session: None,
        };
        let bytes = MAXIMUM_RETAINED_BYTES
            - fixture.catalogs.lock().retained_bytes
            - ToolCatalogs::remote_source_bytes(&CatalogKey::remote("demo", current));
        assert!(bytes <= MAXIMUM_LIST_BYTES);
        let catalog = complete_remote(
            &fixture.catalogs,
            "demo",
            current,
            &page(&["read"], None),
            bytes,
        );
        assert!(
            fixture
                .catalogs
                .lock()
                .servers
                .contains_key(&CatalogKey::remote("demo", oldest))
        );
        assert!(matches!(
            fixture.catalogs.stage(catalog),
            Ok(CatalogStage::Accepted { .. })
        ));
        let inner = fixture.catalogs.lock();
        assert!(
            !inner
                .servers
                .contains_key(&CatalogKey::remote("demo", oldest))
        );
        assert!(
            inner.servers[&CatalogKey::remote("demo", current)]
                .accepted
                .is_some()
        );
        drop(inner);
        assert_remote_retention(&fixture.catalogs);
    }
}
