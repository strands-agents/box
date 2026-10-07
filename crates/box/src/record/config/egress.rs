//! `box.toml`'s `[[egress]]` array: which secret attaches to which request.
//!
//! An entry grants nothing. Naming a destination here makes it reachable by nothing; policy decides
//! that, and this decides only what rides along once it has.
//!
//! | Type | Is |
//! |---|---|
//! | [`EgressEntry`] | one `[[egress]]` table, as the operator writes it |
//! | [`EgressSecret`] | its `secret.*` sub-table |
//! | [`EgressRoute`] | one destination of that entry, resolved |

use credentials::{DestinationPattern, InjectMode, Locator, PhantomCheck, RouteSpec};
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::env::checked_provisioned_name;
use super::{
    AWS_SCHEME, BASIC_AUTH_PLACEMENT, BEARER_PREFIX, CREDSD_SCHEME, DEFAULT_HEADER,
    HEADER_PLACEMENT, INJECT_ALWAYS, INJECT_PHANTOM, QUERY_PARAM_PLACEMENT, URL_PATH_PLACEMENT,
};
use crate::error::{BoxError, ConfigError};

/// The longest a `secret.phantom_prefix` may be; keep in step with `credentials::check_phantom_prefix`.
const PHANTOM_PREFIX_MAX_LEN: usize = 64;

/// Whether `byte` is an RFC 3986 unreserved character; keep in step with
/// `credentials::check_phantom_prefix`.
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

/// Which collection a pair came from. A NAME can be shared across the egress and remote-MCP maps
/// (`[egress.foo]` and `[mcp.foo]`), so identity in `validate_pairs` is `(origin, name)`, never the
/// name alone — otherwise two distinct entries sharing a name look like one entry to the guards.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Origin {
    Egress,
    RemoteMcp,
}

/// Every `[egress.<name>]` credential entry as borrowed `(origin, name, entry)` triples, so a caller
/// can validate one map or the union of several without a shared keyspace collapsing two entries
/// that happen to share a name.
fn as_pairs(entries: &BTreeMap<String, EgressEntry>) -> Vec<(Origin, &str, &EgressEntry)> {
    entries
        .iter()
        .map(|(name, entry)| (Origin::Egress, name.as_str(), entry))
        .collect()
}

/// The operator egress entries and the remote-MCP entries as one triple list. They live in separate
/// maps, so a name shared between `[egress.foo]` and `[mcp.foo]` yields two distinct triples here
/// (distinguished by `Origin`) rather than one overwriting the other.
fn union_pairs<'a>(
    egress: &'a BTreeMap<String, EgressEntry>,
    remote_mcp: &'a BTreeMap<String, EgressEntry>,
) -> Vec<(Origin, &'a str, &'a EgressEntry)> {
    egress
        .iter()
        .map(|(name, entry)| (Origin::Egress, name.as_str(), entry))
        .chain(
            remote_mcp
                .iter()
                .map(|(name, entry)| (Origin::RemoteMcp, name.as_str(), entry)),
        )
        .collect()
}

fn routes_for_pairs(
    entries: &[(Origin, &str, &EgressEntry)],
) -> Result<Vec<EgressRoute>, BoxError> {
    validate_pairs(entries)?;
    let mut bindings = Vec::new();
    for &(_, _, entry) in entries {
        bindings.extend(entry.to_bindings()?);
    }
    Ok(bindings)
}

/// Every distinct `credsd://` environment the given entries name, in declaration order.
fn credsd_environments_of<'a>(entries: impl IntoIterator<Item = &'a EgressEntry>) -> Vec<&'a str> {
    let mut environments: Vec<&str> = Vec::new();
    for entry in entries {
        let Some(secret) = &entry.secret else {
            continue;
        };
        if let Some((SecretScheme::Credsd, environment)) = secret.deliverable()
            && !environment.is_empty()
            && !environments.contains(&environment)
        {
            environments.push(environment);
        }
    }
    environments
}

/// Every distinct `credsd://` environment a box names, across BOTH the operator's `[egress.*]`
/// entries and the remote-MCP entries — they live in separate maps (`record.egress` /
/// `record.remote_mcp`). Passing both is mandatory by construction, so a credsd source declared only
/// on a `[mcp.<name>] type = "http"` server cannot slip past the startup preflight. The preflight
/// validates these against the daemon before the workload runs; a box that names none needs no daemon.
pub(crate) fn credsd_environments<'a>(
    egress: &'a BTreeMap<String, EgressEntry>,
    remote_mcp: &'a BTreeMap<String, EgressEntry>,
) -> Vec<&'a str> {
    credsd_environments_of(egress.values().chain(remote_mcp.values()))
}

#[cfg(test)]
pub(super) fn routes_for(
    entries: &BTreeMap<String, EgressEntry>,
) -> Result<Vec<EgressRoute>, BoxError> {
    routes_for_pairs(&as_pairs(entries))
}

/// Routes for the operator egress entries and the remote-MCP entries together, so the gateway learns
/// every remote MCP host and its credential alongside the plain-HTTP egress.
pub(super) fn routes_for_and_remote(
    egress: &BTreeMap<String, EgressEntry>,
    remote_mcp: &BTreeMap<String, EgressEntry>,
) -> Result<Vec<EgressRoute>, BoxError> {
    routes_for_pairs(&union_pairs(egress, remote_mcp))
}

/// Validate the operator's `[egress.*]` entries alone.
pub(super) fn validate_egress(entries: &BTreeMap<String, EgressEntry>) -> Result<(), ConfigError> {
    validate_pairs(&as_pairs(entries))
}

/// Validate the operator egress entries and the remote-MCP entries together, so a host that names a
/// remote MCP server may name nothing else even though the two are stored in separate collections. A
/// NAME shared between the two (`[egress.foo]` and `[mcp.foo]`) is not a collision: each is its own
/// entry in its own map, and the two are checked as distinct destinations.
pub(super) fn validate_egress_and_remote(
    egress: &BTreeMap<String, EgressEntry>,
    remote_mcp: &BTreeMap<String, EgressEntry>,
) -> Result<(), ConfigError> {
    validate_pairs(&union_pairs(egress, remote_mcp))
}

fn validate_pairs(entries: &[(Origin, &str, &EgressEntry)]) -> Result<(), ConfigError> {
    // Each pattern remembers the entry it came from, so an overlap names both by the name the
    // operator keyed them under rather than quoting two patterns back at them.
    let mut patterns: Vec<(&str, String, DestinationPattern)> = Vec::new();
    // Which entry owns each host, and its protocol. The gateway matches a remote MCP server by host
    // alone, so a host that names an MCP server may name nothing else; a collision is refused here
    // rather than mislabelled there. Keyed by the normalized host so a case- or IP-form-only
    // difference collides here as it does at run time.
    let mut hosts: BTreeMap<String, (Origin, &str, Protocol)> = BTreeMap::new();
    for &(origin, name, entry) in entries {
        entry.validate()?;
        // A remote MCP server's name is its `context.input.server`, which a rule reads to gate its
        // tool calls. It must be present and nameable: empty leaves it nameless, and a control
        // character (a newline) could break out of a policy comment and inject a rule.
        if entry.protocol == Protocol::Mcp {
            if name.is_empty() {
                return Err(ConfigError::Credential {
                    host: entry.destinations.first().cloned().unwrap_or_default(),
                    reason: "a remote MCP server needs a name: it becomes `context.input.server`, \
                             which a policy rule reads to gate its tool calls"
                        .to_string(),
                });
            }
            if let Some(bad) = name.chars().find(|c| !crate::record::config::nameable(*c)) {
                return Err(ConfigError::Credential {
                    host: entry.destinations.first().cloned().unwrap_or_default(),
                    reason: format!(
                        "a remote MCP server name is `context.input.server` and is rendered into \
                         the policy, so it may hold only letters, digits, '.', '_', and '-'; \
                         `{name}` contains {bad:?}"
                    ),
                });
            }
        }
        for destination in &entry.destinations {
            // A host that names an MCP server may name nothing else, because `mcp_server_for` is
            // port-blind: a second MCP server or a plain-HTTP target on the same host would have its
            // traffic classified as this server's. Two non-MCP entries on one host are left to the
            // overlap check below, which is the credential-authority rule.
            let host = normalized_host(host_of(destination));
            if let Some((earlier_origin, earlier, earlier_protocol)) =
                hosts.insert(host.clone(), (origin, name, entry.protocol))
                && (earlier_origin, earlier) != (origin, name)
                && (entry.protocol == Protocol::Mcp || earlier_protocol == Protocol::Mcp)
            {
                return Err(ConfigError::Credential {
                    host: host.clone(),
                    reason: format!(
                        "`{name}` and `{earlier}` both name host {host:?}; the gateway routes a \
                         remote MCP server by host alone, so a host that names an MCP server may \
                         name nothing else"
                    ),
                });
            }
            let pattern = entry.pattern(destination)?;
            if let Some((earlier, host, _)) = patterns
                .iter()
                .find(|(_, _, existing)| existing.overlaps(&pattern))
            {
                return Err(ConfigError::Credential {
                    host: destination.clone(),
                    reason: format!(
                        "`{name}` overlaps `{earlier}` at {host:?}; one destination is one \
                         credential authority, and a request matching both has no unambiguous secret"
                    ),
                });
            }
            patterns.push((name, destination.clone(), pattern));
        }
    }
    Ok(())
}

/// One egress route: which secret attaches at which destination.
pub(crate) struct EgressRoute {
    /// The exact destination this binding governs, port included.
    destination: DestinationPattern,

    /// The host as the operator authored it, for diagnostics.
    host: String,

    /// The pointer to the host-side secret.
    locator: Locator,

    /// The environment variable a phantom is provisioned under.
    provisioned_name: Option<String>,

    /// Where the credential is attached.
    placement: Placement,

    /// How strictly the gateway checks the placeholder before it injects the real secret.
    phantom: PhantomCheck,

    /// The literal prefix the minted phantom carries, or `None` for the vault's default.
    phantom_prefix: Option<String>,
}

/// Where a credential lands on an outbound request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Placement {
    /// Attached at one location: `name: <prefix><secret>`.
    Header {
        /// The header name, as authored or defaulted to `Authorization`.
        name: String,
        /// The literal text prepended to the credential in the header value.
        prefix: String,
    },

    /// Attached as HTTP Basic auth, with the credential as the password half.
    BasicAuth,

    /// Attached as the query parameter `name`.
    QueryParam {
        /// The query-parameter name the credential is attached under.
        name: String,
    },

    /// Signed across several headers inside the boundary, so it has no single
    /// attach location and mints no phantom.
    SignedInBoundary,
}

impl EgressRoute {
    pub(crate) fn destination(&self) -> &DestinationPattern {
        &self.destination
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn provisioned_name(&self) -> Option<&str> {
        self.provisioned_name.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn phantom(&self) -> PhantomCheck {
        self.phantom
    }

    #[cfg(test)]
    pub(crate) fn phantom_prefix(&self) -> Option<&str> {
        self.phantom_prefix.as_deref()
    }

    pub(crate) fn to_route_spec(&self) -> Result<RouteSpec, ConfigError> {
        Ok(match self.placement.inject_mode(&self.host)? {
            // The harness location defaults to the inject location: the workload presents
            // the phantom where the real credential will go.
            Some(mode) => {
                let spec = RouteSpec::opaque(self.destination.clone(), self.locator.clone(), mode)
                    .phantom_check(self.phantom);
                match &self.phantom_prefix {
                    // `validate` already refused an unsafe prefix.
                    Some(prefix) => spec.phantom_prefix(prefix.clone()).map_err(|source| {
                        ConfigError::Credential {
                            host: self.host.clone(),
                            reason: source.to_string(),
                        }
                    })?,
                    None => spec,
                }
            }
            None => RouteSpec::signed_aws(self.destination.clone(), self.locator.clone()),
        })
    }
}

impl Placement {
    /// The inject mode this placement describes, or `None` when the credential
    /// is signed across several headers and so has no single location.
    fn inject_mode(&self, host: &str) -> Result<Option<InjectMode>, ConfigError> {
        let mode = match self {
            Self::Header { name, prefix } => InjectMode::header(
                format!("{prefix}{{}}"),
                (!name.eq_ignore_ascii_case(DEFAULT_HEADER)).then(|| name.to_string()),
            )
            .map_err(|source| ConfigError::Credential {
                host: host.to_string(),
                reason: source.to_string(),
            })?,
            Self::BasicAuth => InjectMode::basic_auth(),
            Self::QueryParam { name } => {
                InjectMode::query_param(name).map_err(|source| ConfigError::Credential {
                    host: host.to_string(),
                    reason: source.to_string(),
                })?
            }
            Self::SignedInBoundary => return Ok(None),
        };
        Ok(Some(mode))
    }
}

/// One `[egress.<name>]`: an outbound target, what it speaks, and which secret rides its requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EgressEntry {
    /// The destinations this entry governs. Each is a host, `host:port`, a path prefix or `/*`
    /// suffix, or a `*.`/bare `*` wildcard, in any combination.
    pub(crate) destinations: Vec<String>,

    /// What the destination speaks. `mcp` tells the gateway to parse JSON-RPC frames and raise
    /// `mcp:call`; `http` is an ordinary request.
    #[serde(default, skip_serializing_if = "Protocol::is_http")]
    pub(crate) protocol: Protocol,

    /// Which secret to attach, and where it lands. Absent for a target that needs none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) secret: Option<EgressSecret>,
}

/// What an egress destination speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Protocol {
    /// An ordinary HTTP request.
    #[default]
    Http,
    /// A remote MCP server the gateway gates per tool call.
    Mcp,
}

impl Protocol {
    pub(crate) fn is_http(&self) -> bool {
        matches!(self, Protocol::Http)
    }
}

/// Which scheme a `[[egress]]` secret names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretScheme {
    /// `env://NAME`: a variable the workload presents as a phantom.
    Env,
    /// `aws://profile`: signed in the boundary, so nothing is placed.
    Aws,
    /// `credsd://environment`: a credsd credential. It signs in the boundary; the daemon's
    /// `material.type` picks the signer per request, and the entry names no credential type.
    Credsd,
}

/// Which secret an entry attaches, and where it lands on the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EgressSecret {
    /// The secret to attach, as a URI: `env://NAME` or `aws://profile`.
    #[serde(rename = "ref")]
    pub(crate) reference: String,

    /// The header to attach it under. Defaults to `Authorization`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) header: Option<String>,

    /// The literal text before the secret. Defaults to `Bearer ` on `Authorization` and to
    /// empty elsewhere, matching the convention each header carries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) prefix: Option<String>,

    /// Where the secret lands: `header`, `basic_auth`, or `query_param`. Defaults to `header`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) placement: Option<String>,

    /// The query-parameter name, required by and only valid for `placement = "query_param"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) param: Option<String>,

    /// When the gateway attaches the real secret: `phantom` (the default) only on a request that
    /// carries the route's phantom, `always` on every request to the destinations. Valid only for
    /// an `env://` route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) inject: Option<String>,

    /// The literal prefix the minted phantom carries, before its random suffix. Defaults to
    /// `strands_box_`. Valid only for an `env://` route, so a harness that checks its key format
    /// accepts the injected phantom.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) phantom_prefix: Option<String>,
}

impl EgressSecret {
    /// The scheme this secret names and the value behind it, or `None` when the box cannot deliver
    /// it.
    fn deliverable(&self) -> Option<(SecretScheme, &str)> {
        let (scheme, value) = self.reference.split_once("://")?;
        let scheme = match scheme {
            "env" => SecretScheme::Env,
            AWS_SCHEME => SecretScheme::Aws,
            CREDSD_SCHEME => SecretScheme::Credsd,
            _ => return None,
        };
        Some((scheme, value))
    }

    /// The placeholder-check mode this secret selects. `validate` already refused every spelling but
    /// `phantom`/`always`/absent, so an absent or unknown value defaults to the fail-closed mode.
    fn phantom_check(&self) -> PhantomCheck {
        match self.inject.as_deref() {
            Some(INJECT_ALWAYS) => PhantomCheck::Advisory,
            _ => PhantomCheck::Strict,
        }
    }
}

impl EgressEntry {
    fn pattern(&self, destination: &str) -> Result<DestinationPattern, ConfigError> {
        DestinationPattern::parse(destination).map_err(|source| ConfigError::Credential {
            host: destination.to_string(),
            reason: source.to_string(),
        })
    }

    /// Whether this credential signs in-boundary instead of attaching at one location. An `aws://`
    /// profile and a `credsd://` source both sign.
    fn signs_in_boundary(secret: &EgressSecret) -> bool {
        matches!(
            secret.deliverable(),
            Some((SecretScheme::Aws | SecretScheme::Credsd, _))
        )
    }

    fn placement(secret: &EgressSecret) -> Placement {
        if Self::signs_in_boundary(secret) {
            return Placement::SignedInBoundary;
        }
        // `validate` already refused every spelling but these, so an unknown value cannot
        // happen. Defaulting to header placement keeps this function total without a panic.
        match secret.placement.as_deref() {
            Some(BASIC_AUTH_PLACEMENT) => Placement::BasicAuth,
            Some(QUERY_PARAM_PLACEMENT) => Placement::QueryParam {
                name: secret.param.clone().unwrap_or_default(),
            },
            _ => {
                let name = secret.header.as_deref().unwrap_or(DEFAULT_HEADER);
                let prefix = secret.prefix.clone().unwrap_or_else(|| {
                    if name.eq_ignore_ascii_case(DEFAULT_HEADER) {
                        BEARER_PREFIX.to_string()
                    } else {
                        String::new()
                    }
                });
                Placement::Header {
                    name: name.to_string(),
                    prefix,
                }
            }
        }
    }

    /// Translate into the box's validated binding vocabulary, one binding per destination.
    ///
    /// An entry with no secret (a remote MCP target that needs none) contributes no binding.
    pub(crate) fn to_bindings(&self) -> Result<Vec<EgressRoute>, BoxError> {
        let Some(secret) = &self.secret else {
            return Ok(Vec::new());
        };
        let locator =
            Locator::parse_uri(&secret.reference).map_err(|source| ConfigError::Locator {
                locator: secret.reference.clone(),
                source,
            })?;
        let mut bindings = Vec::with_capacity(self.destinations.len());
        for destination in &self.destinations {
            // Only an `env://` secret has a name to provision a phantom under. Every other scheme
            // resolves host-side, with nothing placed in the workload's environment.
            let provisioned_name = match secret.deliverable() {
                Some((SecretScheme::Env, name)) => {
                    Some(checked_provisioned_name(destination, name)?)
                }
                _ => None,
            };
            bindings.push(EgressRoute {
                destination: self.pattern(destination)?,
                host: destination.clone(),
                locator: locator.clone(),
                provisioned_name,
                placement: Self::placement(secret),
                phantom: secret.phantom_check(),
                phantom_prefix: secret.phantom_prefix.clone(),
            });
        }
        Ok(bindings)
    }

    /// Reject one declared destination this file is not allowed to express.
    fn validate_destination(&self, destination: &str) -> Result<(), ConfigError> {
        let refuse = |reason: &str| {
            Err(ConfigError::Credential {
                host: destination.to_string(),
                reason: reason.to_string(),
            })
        };

        if destination.is_empty() {
            return refuse("destination is empty");
        }
        if destination.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return refuse("destination contains whitespace");
        }
        // An all-hosts pattern would attach one credential to every request policy permits,
        // including hosts the operator never considered.
        if self.pattern(destination)?.matches_every_host() {
            return refuse(
                "destination must name something narrower: this matches every host, so it \
                 would attach this secret to every permitted request — a wildcard needs a \
                 domain such as *.example.com",
            );
        }

        // Port 0 survives `DestinationPattern::parse`, which only range-checks the u16. Nothing
        // listens there, so a destination naming it declares a secret for a request that cannot
        if let Some(port) = declared_port(destination)
            && port == 0
        {
            return refuse("port must be between 1 and 65535");
        }
        Ok(())
    }

    /// Reject an entry this file is not allowed to express.
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        // The label an entry-level refusal names. The first destination is what an operator
        // reads the entry by; an entry with none is refused before this is used.
        let label = self.destinations.first().cloned().unwrap_or_default();
        let refuse = |reason: &str| {
            Err(ConfigError::Credential {
                host: label.clone(),
                reason: reason.to_string(),
            })
        };

        if self.destinations.is_empty() {
            return Err(ConfigError::Credential {
                host: self
                    .secret
                    .as_ref()
                    .map(|secret| secret.reference.clone())
                    .unwrap_or_default(),
                reason: "`destinations` is empty; an entry with no destination attaches its \
                         secret to nothing"
                    .to_string(),
            });
        }
        for destination in &self.destinations {
            self.validate_destination(destination)?;
        }

        let Some(secret) = &self.secret else {
            // No secret. Only a protocol that needs none may omit it; a bare `http` entry declares
            // only a destination, which policy already decides.
            if self.protocol == Protocol::Http {
                return refuse(
                    "an entry with no secret declares only a destination, which policy already \
                     decides; give it a secret, or set protocol = \"mcp\" for a remote MCP server",
                );
            }
            return Ok(());
        };

        if secret.reference.is_empty() {
            return refuse(
                "secret is required: an entry with no secret declares only a destination, \
                 which policy already decides",
            );
        }
        let Some((scheme, _)) = secret.reference.split_once("://") else {
            return refuse("secret must be a URI such as env://NAME or aws://profile");
        };

        // Only a scheme the box can actually deliver. `env://` names a variable to seed the phantom
        // into, and `aws://` needs none, because the signer places the signature. Every other
        if secret.deliverable().is_none() {
            return refuse(&format!(
                "secret scheme {scheme:?} is not one the box can deliver: use env://NAME for a \
                 credential the workload presents as a placeholder, aws://profile for one signed \
                 in the boundary, or credsd://<environment> for a credsd-vended credential"
            ));
        }

        // A `credsd://` source names a daemon environment and no credential type: the box infers the
        // type from the `credential/get` response's `material.type` per request. The box
        // carries no `secret.type` key, so `deny_unknown_fields` refuses one on any scheme.
        if let Some((SecretScheme::Credsd, environment)) = secret.deliverable()
            && environment.is_empty()
        {
            return refuse(
                "a credsd:// reference must name an environment, as in credsd://prod-inference",
            );
        }

        // A signature spans several headers, so naming one header for it describes something the
        // mechanism cannot do.
        if Self::signs_in_boundary(secret)
            && (secret.header.is_some()
                || secret.prefix.is_some()
                || secret.placement.is_some()
                || secret.param.is_some())
        {
            return refuse(
                "a signed AWS secret (aws:// or a credsd:// source) is signed in-boundary \
                 across several headers, so it takes no header, prefix, placement, or param",
            );
        }

        // The injection mode tunes the phantom swap, which only an `env://` route performs. A
        // signed route mints no phantom, so the key has no meaning there.
        if secret.inject.is_some() && !matches!(secret.deliverable(), Some((SecretScheme::Env, _)))
        {
            return refuse(
                "inject tunes the env:// phantom swap, so it belongs only with an env:// \
                 reference; a signed route (aws:// or credsd://) mints no phantom to check",
            );
        }
        if let Some(mode) = &secret.inject
            && mode != INJECT_PHANTOM
            && mode != INJECT_ALWAYS
        {
            return refuse(&format!(
                "inject {mode:?} is not one of \"phantom\" or \"always\""
            ));
        }

        // The phantom prefix shapes the minted placeholder, which only an `env://` route mints. A
        // signed route mints none, so the key has no meaning there.
        if secret.phantom_prefix.is_some()
            && !matches!(secret.deliverable(), Some((SecretScheme::Env, _)))
        {
            return refuse(
                "phantom_prefix sets the minted phantom's prefix, so it belongs only with an \
                 env:// reference; a signed route (aws:// or credsd://) mints no phantom",
            );
        }
        if let Some(prefix) = &secret.phantom_prefix {
            if prefix.is_empty() {
                return refuse(
                    "phantom_prefix is empty; omit the key for the default strands_box_ prefix",
                );
            }
            if prefix.len() > PHANTOM_PREFIX_MAX_LEN {
                return refuse(&format!(
                    "phantom_prefix must be at most {PHANTOM_PREFIX_MAX_LEN} characters"
                ));
            }
            if let Some(byte) = prefix.bytes().find(|byte| !is_unreserved(*byte)) {
                return refuse(&format!(
                    "phantom_prefix character {:?} is not one of A-Z, a-z, 0-9, '-', '_', '.', '~'",
                    byte as char
                ));
            }
        }

        // Where the credential lands. `url_path` is named explicitly rather than falling into the
        // unknown-value branch, so an operator learns it is withheld and not misspelled: its secret
        match secret.placement.as_deref() {
            None | Some(HEADER_PLACEMENT) => {
                if secret.param.is_some() {
                    return refuse(
                        "param names a query parameter, so it belongs only with \
                         secret.placement = \"query_param\"",
                    );
                }
            }
            Some(BASIC_AUTH_PLACEMENT) => {
                if secret.header.is_some() || secret.prefix.is_some() {
                    return refuse(
                        "placement = \"basic_auth\" attaches to Authorization as a \
                         Basic pair, so it takes no header or prefix",
                    );
                }
                if secret.param.is_some() {
                    return refuse("param belongs only with placement = \"query_param\"");
                }
            }
            Some(QUERY_PARAM_PLACEMENT) => {
                if secret.header.is_some() || secret.prefix.is_some() {
                    return refuse(
                        "placement = \"query_param\" attaches to the query string, so \
                         it takes no header or prefix",
                    );
                }
                match &secret.param {
                    None => {
                        return refuse(
                            "placement = \"query_param\" needs credential_param to \
                             name the parameter",
                        );
                    }
                    Some(param) => {
                        // Asked of the vault's constructor, which owns the rule, so the refusal
                        // lands at `configure` rather than at daemon start.
                        if let Err(source) = InjectMode::query_param(param.clone()) {
                            return refuse(&source.to_string());
                        }
                    }
                }
            }
            Some(URL_PATH_PLACEMENT) => {
                return refuse(
                    "placement = \"url_path\" is not available in this version: a \
                     path-spliced credential reaches the request path, which policy and audit \
                     inputs read. Use \"header\", \"basic_auth\", or \"query_param\"",
                );
            }
            Some(other) => {
                return refuse(&format!(
                    "placement {other:?} is not one of \"header\", \"basic_auth\", \
                     or \"query_param\""
                ));
            }
        }

        if let Some(header) = &secret.header {
            if header.is_empty() {
                return refuse("header is empty");
            }
            // Asked of the type that owns the rule rather than re-implemented here. A header name
            // is an RFC 7230 token, or a config value could forge a header boundary on the wire,
            if let Err(source) = InjectMode::header("{}", Some(header.clone())) {
                return refuse(&source.to_string());
            }
        }
        if let Some(prefix) = &secret.prefix
            && prefix.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return refuse("prefix contains a control character");
        }

        // Braces at `configure`, not at start. The prefix is concatenated into a `{}`-substituted
        // template, so an operator's braces would consume the substitution slot the secret goes
        if let Some(prefix) = &secret.prefix
            && (prefix.contains('{') || prefix.contains('}'))
        {
            return refuse(
                "prefix carries no braces: it is prepended to the credential, and a \
                 brace there would consume the substitution slot the secret goes into",
            );
        }

        Ok(())
    }
}

/// The explicitly declared port of one destination, if its authority carries one.
fn declared_port(destination: &str) -> Option<u16> {
    let authority = destination.split('/').next()?;
    authority.rsplit_once(':')?.1.parse().ok()
}

/// The host of a destination: its authority with any scheme, path, port, or IPv6 brackets stripped.
///
/// The gateway matches a connecting host against this to recognize a remote MCP server. It is the
/// one host extractor, so the write and the match paths cannot derive a host two ways and drift.
pub(crate) fn host_of(destination: &str) -> &str {
    let after_scheme = destination
        .split_once("://")
        .map_or(destination, |(_, rest)| rest);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if authority.matches(':').count() > 1 {
        // A bare IPv6 address: without brackets a port cannot be told from the address, so keep the
        // whole authority rather than truncate it at the last colon.
        authority
    } else {
        authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host)
    }
}

/// The host key the config-time collision check and the runtime match must agree on: an IP in its
/// canonical form, otherwise the lowercased DNS name, because `connect::same_host` compares a DNS
/// name case-insensitively and an IP through `IpAddr`.
fn normalized_host(host: &str) -> String {
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse `[[egress]]` the way `box.toml` delivers it, and run the structural check.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        #[serde(default)]
        egress: BTreeMap<String, EgressEntry>,
    }

    fn load(text: &str) -> Result<BTreeMap<String, EgressEntry>, ConfigError> {
        let fixture: Fixture = toml::from_str(text).expect("test config parses");
        validate_egress(&fixture.egress)?;
        Ok(fixture.egress)
    }

    /// One present variable accepted for credential projection.
    fn present_variable() -> String {
        std::env::vars_os()
            .find_map(|(name, _)| {
                let name = name.into_string().ok()?;
                crate::record::config::env::checked_provisioned_name("api.test", &name).ok()
            })
            .expect("the test process has a valid credential variable")
    }

    #[test]
    fn the_default_placement_is_a_bearer_authorization_header() {
        let entries = load(
            r#"
            [egress.a]
            destinations = ["api.stripe.com"]
            secret.ref = "env://TOKEN"
            "#,
        )
        .expect("valid");
        assert_eq!(
            EgressEntry::placement(entries["a"].secret.as_ref().expect("secret")),
            Placement::Header {
                name: "Authorization".to_string(),
                prefix: "Bearer ".to_string(),
            }
        );
    }

    #[test]
    fn inject_defaults_to_phantom_and_always_threads_through() {
        let variable = present_variable();
        let strict = load(&format!(
            r#"
            [egress.a]
            destinations = ["api.stripe.com"]
            secret.ref = "env://{variable}"
            "#,
        ))
        .expect("valid");
        assert_eq!(
            routes_for(&strict).expect("bindings build")[0].phantom(),
            PhantomCheck::Strict,
            "an absent key defaults to the fail-closed check"
        );

        let always = load(&format!(
            r#"
            [egress.a]
            destinations = ["api.stripe.com"]
            secret.ref = "env://{variable}"
            secret.inject = "always"
            "#,
        ))
        .expect("valid");
        assert_eq!(
            routes_for(&always).expect("bindings build")[0].phantom(),
            PhantomCheck::Advisory,
            "always threads from box.toml to the route"
        );

        let phantom = load(&format!(
            r#"
            [egress.a]
            destinations = ["api.stripe.com"]
            secret.ref = "env://{variable}"
            secret.inject = "phantom"
            "#,
        ))
        .expect("valid");
        assert_eq!(
            routes_for(&phantom).expect("bindings build")[0].phantom(),
            PhantomCheck::Strict,
            "phantom is the fail-closed check, written out"
        );
    }

    #[test]
    fn an_unknown_inject_is_refused() {
        let error = load(
            r#"
            [egress.a]
            destinations = ["api.stripe.com"]
            secret.ref = "env://TOKEN"
            secret.inject = "loose"
            "#,
        )
        .expect_err("an unknown mode is refused");
        let message = error.to_string();
        assert!(
            message.contains("\"phantom\"") && message.contains("\"always\""),
            "the refusal names the two valid values: {message}"
        );
    }

    /// A signed route mints no placeholder, so it refuses `secret.inject` — for an `aws://`
    /// profile and for a `credsd://` source alike, since a credsd route always signs.
    #[test]
    fn inject_is_refused_beside_a_signed_route() {
        for reference in ["aws://default", "credsd://prod"] {
            let error = load(&format!(
                "[egress.a]\ndestinations = [\"bedrock.us-east-1.amazonaws.com\"]\nsecret.ref = {reference:?}\nsecret.inject = \"always\"\n"
            ))
            .expect_err("a signed route mints no placeholder to check");
            assert!(
                error.to_string().contains("env://"),
                "{reference}: the refusal explains the key belongs with an env:// route: {error}"
            );
        }
    }

    #[test]
    fn phantom_prefix_is_accepted_and_threads_through() {
        let variable = present_variable();
        let entries = load(&format!(
            r#"
            [egress.a]
            destinations = ["api.anthropic.com"]
            secret.ref = "env://{variable}"
            secret.phantom_prefix = "sk-ant-"
            "#,
        ))
        .expect("valid");
        assert_eq!(
            routes_for(&entries).expect("bindings build")[0].phantom_prefix(),
            Some("sk-ant-"),
            "the prefix threads from box.toml to the route"
        );
    }

    #[test]
    fn an_absent_phantom_prefix_leaves_the_route_default() {
        let variable = present_variable();
        let entries = load(&format!(
            r#"
            [egress.a]
            destinations = ["api.anthropic.com"]
            secret.ref = "env://{variable}"
            "#,
        ))
        .expect("valid");
        assert_eq!(
            routes_for(&entries).expect("bindings build")[0].phantom_prefix(),
            None,
            "an absent key leaves the vault's default prefix"
        );
    }

    #[test]
    fn an_unsafe_phantom_prefix_is_refused() {
        for prefix in ["", "sk ant", "sk/ant"] {
            let error = load(&format!(
                r#"
                [egress.a]
                destinations = ["api.anthropic.com"]
                secret.ref = "env://TOKEN"
                secret.phantom_prefix = "{prefix}"
                "#,
            ))
            .expect_err("an unsafe prefix is refused");
            assert!(
                error.to_string().contains("phantom_prefix"),
                "the refusal names the key: {error}"
            );
        }
    }

    #[test]
    fn phantom_prefix_is_refused_beside_a_signed_route() {
        let error = load(
            r#"
            [egress.a]
            destinations = ["bedrock.us-east-1.amazonaws.com"]
            secret.ref = "aws://default"
            secret.phantom_prefix = "sk-ant-"
            "#,
        )
        .expect_err("a signed route mints no phantom");
        assert!(
            error.to_string().contains("env://"),
            "the refusal explains the key belongs with an env:// route: {error}"
        );
    }

    #[test]
    fn a_named_header_defaults_to_a_raw_value() {
        // `x-api-key: <secret>` carries no `Bearer ` convention, so the prefix defaults
        // to empty.
        let entries = load(
            r#"
            [egress.a]
            destinations = ["api.anthropic.com"]
            secret.ref = "env://TOKEN"
            secret.header = "x-api-key"
            "#,
        )
        .expect("valid");
        assert_eq!(
            EgressEntry::placement(entries["a"].secret.as_ref().expect("secret")),
            Placement::Header {
                name: "x-api-key".to_string(),
                prefix: String::new(),
            }
        );
    }

    #[test]
    fn an_explicit_prefix_overrides_the_convention() {
        let entries = load(
            r#"
            [egress.a]
            destinations = ["api.example.com"]
            secret.ref = "env://TOKEN"
            secret.prefix = "Token "
            "#,
        )
        .expect("valid");
        assert_eq!(
            EgressEntry::placement(entries["a"].secret.as_ref().expect("secret")),
            Placement::Header {
                name: "Authorization".to_string(),
                prefix: "Token ".to_string(),
            }
        );
    }

    #[test]
    fn a_port_is_honored_and_zero_is_refused() {
        let entries = load(
            r#"
            [egress.a]
            destinations = ["api.internal.test:8443"]
            secret.ref = "env://TOKEN"
            "#,
        )
        .expect("valid");
        assert_eq!(
            entries["a"].pattern(&entries["a"].destinations[0]).unwrap(),
            DestinationPattern::parse("api.internal.test:8443").unwrap()
        );

        for host in ["api.test:0", "api.test:notaport", "api.test:99999"] {
            assert!(
                load(&format!(
                    "[egress.b]\ndestinations = [{host:?}]\nsecret.ref = \"env://T\""
                ))
                .is_err(),
                "host {host:?} must be refused"
            );
        }
    }

    #[test]
    fn a_target_the_mechanism_cannot_honor_is_refused() {
        // A host pattern is not refused any more: a target attaches a credential to
        // requests the policy already permitted, so a wildcard or path narrows what carries
        for (text, why) in [
            (
                "[egress.a]\ndestinations = [\"api.example.com\"]\nsecret.ref = \"\"",
                "empty credential",
            ),
            (
                "[egress.b]\ndestinations = [\"\"]\nsecret.ref = \"env://T\"",
                "empty host",
            ),
            (
                "[egress.c]\ndestinations = [\"*\"]\nsecret.ref = \"env://T\"",
                "bare wildcard attaches to every permitted request",
            ),
            (
                "[egress.d]\ndestinations = [\"api example.com\"]\nsecret.ref = \"env://T\"",
                "whitespace in host",
            ),
            (
                "[egress.e]\ndestinations = [\"*.*\"]\nsecret.ref = \"env://T\"",
                "misplaced wildcard",
            ),
        ] {
            assert!(load(text).is_err(), "{why} must be refused");
        }
    }

    #[test]
    fn a_host_may_be_a_pattern() {
        for host in [
            "*.anthropic.com",
            "api.example.com/v1/",
            "api.example.com:8443",
            "*.example.com/v1/",
        ] {
            let entries = load(&format!(
                "[egress.a]\ndestinations = [{host:?}]\nsecret.ref = \"env://T\""
            ))
            .unwrap_or_else(|error| panic!("{host} must be accepted: {error}"));
            assert_eq!(entries["a"].destinations[0], host);
        }
    }

    /// An all-hosts host is refused however it is spelled.
    #[test]
    fn an_all_hosts_host_is_refused_however_it_is_spelled() {
        for host in [
            "*", "*/", "*/v1/", // The family the text comparison missed.
            "*:443", "*:80", "*:8443", "*:443/v1",
        ] {
            let error = load(&format!(
                "[egress.a]\ndestinations = [{host:?}]\nsecret.ref = \"env://T\""
            ))
            .expect_err(&format!("{host} matches every host and must be refused"));

            let message = error.to_string();
            assert!(
                message.contains(host),
                "the refusal must name the host as written: {message}"
            );
        }
    }

    #[test]
    fn overlapping_hosts_are_refused() {
        for (a, b, why) in [
            ("api.stripe.com", "api.stripe.com", "identical"),
            (
                "api.stripe.com",
                "api.stripe.com:443",
                "implicit vs explicit :443",
            ),
            (
                "*.stripe.com",
                "api.stripe.com",
                "wildcard covers the exact host",
            ),
            (
                "*.stripe.com",
                "*.api.stripe.com",
                "one suffix inside the other",
            ),
        ] {
            let text = format!(
                "[egress.a]\ndestinations = [{a:?}]\nsecret.ref = \"env://ONE\"\n\n\
                 [egress.b]\ndestinations = [{b:?}]\nsecret.ref = \"env://TWO\""
            );
            let error = load(&text)
                .err()
                .unwrap_or_else(|| panic!("{why}: {a} and {b} must be refused as overlapping"));
            assert!(
                error.to_string().contains("overlaps"),
                "{why}: error should name the overlap: {error}"
            );
        }
    }

    /// An overlap is refused within one entry as well as across two.
    #[test]
    fn an_overlap_inside_one_entry_is_refused() {
        let error = load(
            r#"
            [egress.a]
            destinations = ["*.stripe.com", "api.stripe.com"]
            secret.ref = "env://ONE"
            "#,
        )
        .expect_err("two overlapping destinations in one entry must be refused");
        assert!(error.to_string().contains("overlaps"), "{error}");

        // And an entry with no destination attaches its secret to nothing.
        let empty = load(
            r#"
            [egress.b]
            destinations = []
            secret.ref = "env://ONE"
            "#,
        )
        .expect_err("an entry with no destination must be refused");
        assert!(empty.to_string().contains("empty"), "{empty}");
    }

    /// Two remote MCP servers on one host are refused, even on distinct ports.
    ///
    /// The gateway matches a server by host alone, so a second entry on the same host would tag its
    /// traffic with the first's `context.input.server`. The overlap check above misses this, because
    /// two distinct explicit ports do not overlap.
    #[test]
    fn two_mcp_servers_on_one_host_are_refused() {
        let error = load(
            r#"
            [egress.prod]
            protocol = "mcp"
            destinations = ["mcp.example.com:443"]

            [egress.staging]
            protocol = "mcp"
            destinations = ["mcp.example.com:8443"]
            "#,
        )
        .expect_err("two mcp servers on one host must be refused");
        assert!(
            error.to_string().contains("name nothing else"),
            "the refusal must name the one-host-one-server rule: {error}"
        );

        // Differing only in host case is the same collision at run time, because `same_host` is
        // case-insensitive. The normalized key must catch it.
        load(
            r#"
            [egress.prod]
            protocol = "mcp"
            destinations = ["mcp.EXAMPLE.com:443"]

            [egress.staging]
            protocol = "mcp"
            destinations = ["mcp.example.com:8443"]
            "#,
        )
        .expect_err("two mcp servers on one host differing only in case must be refused");

        // One server may name its own host on more than one port; that is one server, not two.
        load(
            r#"
            [egress.demo]
            protocol = "mcp"
            destinations = ["mcp.example.com:443", "mcp.example.com:8443"]
            "#,
        )
        .expect("one server may name its host more than once");

        // Two servers on distinct hosts are unambiguous.
        load(
            r#"
            [egress.one]
            protocol = "mcp"
            destinations = ["one.example.com"]

            [egress.two]
            protocol = "mcp"
            destinations = ["two.example.com"]
            "#,
        )
        .expect("two servers on distinct hosts are unambiguous");
    }

    /// A host that names an MCP server may name nothing else — not a plain-HTTP target either.
    ///
    /// `mcp_server_for` is port-blind, so the HTTP target's traffic would be fed to the MCP
    /// classifier and fail closed. Two plain-HTTP entries on one host stay a matter for the overlap
    /// check, not this one.
    #[test]
    fn an_mcp_server_may_not_share_a_host_with_a_plain_http_entry() {
        let error = load(
            r#"
            [egress.http_svc]
            destinations = ["api.example.com:80"]
            secret.ref = "env://TOKEN"

            [egress.mcp_svc]
            protocol = "mcp"
            destinations = ["api.example.com:8443"]
            "#,
        )
        .expect_err("an mcp server must not share a host with a plain-http entry");
        assert!(
            error.to_string().contains("name nothing else"),
            "the refusal must name the one-host rule: {error}"
        );

        // But two plain-HTTP entries on one host, distinct ports, are not this rule's concern.
        load(
            r#"
            [egress.a]
            destinations = ["api.example.com:80"]
            secret.ref = "env://ONE"

            [egress.b]
            destinations = ["api.example.com:8443"]
            secret.ref = "env://TWO"
            "#,
        )
        .expect("two plain-http entries on one host with distinct ports are allowed");
    }

    /// A remote MCP server name is `context.input.server` and is rendered into the starter policy,
    /// so a control character in it is refused rather than written into a policy comment.
    #[test]
    fn a_remote_mcp_server_name_must_be_nameable() {
        let error = load(
            "[egress.\"ev\\nil\"]\nprotocol = \"mcp\"\ndestinations = [\"mcp.example.com\"]\n",
        )
        .expect_err("a control character in a remote MCP name must be refused");
        assert!(
            error.to_string().contains("letters, digits"),
            "the refusal must name the character rule: {error}"
        );
    }

    /// `host_of` keeps a bare IPv6 whole rather than truncating it at the last colon.
    #[test]
    fn host_of_keeps_a_bare_ipv6_whole() {
        assert_eq!(host_of("2001:db8::1"), "2001:db8::1");
        assert_eq!(host_of("[2001:db8::1]:8931"), "2001:db8::1");
        assert_eq!(host_of("https://[2001:db8::1]/mcp"), "2001:db8::1");
        assert_eq!(host_of("mcp.example.com:8931"), "mcp.example.com");
        assert_eq!(host_of("mcp.example.com"), "mcp.example.com");
    }

    #[test]
    fn disjoint_hosts_are_allowed() {
        let entries = load(
            r#"
            [egress.a]
            destinations = ["*.anthropic.com"]
            secret.ref = "env://ANTHROPIC"

            [egress.b]
            destinations = ["api.stripe.com"]
            secret.ref = "env://STRIPE"

            [egress.c]
            destinations = ["api.stripe.com:8443"]
            secret.ref = "env://STRIPE_STAGING"
            "#,
        )
        .expect("disjoint hosts are independent");
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn a_locator_must_be_a_uri() {
        assert!(
            load("[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = \"STRIPE_KEY\"").is_err(),
            "a bare variable name is not a locator"
        );
    }

    #[test]
    fn an_aws_locator_takes_no_header_or_prefix() {
        let ok = load(
            r#"
            [egress.a]
            destinations = ["bedrock-runtime.us-west-2.amazonaws.com"]
            secret.ref = "aws://prod"
            "#,
        )
        .expect("an aws route with no header is valid");
        assert!(EgressEntry::signs_in_boundary(
            ok["a"].secret.as_ref().expect("secret")
        ));

        for extra in [
            "secret.header = \"x-api-key\"",
            "secret.prefix = \"Bearer \"",
        ] {
            assert!(
                load(&format!(
                    "[egress.b]\ndestinations = [\"bedrock.amazonaws.com\"]\nsecret.ref = \"aws://prod\"\n{extra}"
                ))
                .is_err(),
                "an aws route must refuse {extra}"
            );
        }
    }

    #[test]
    fn two_entries_on_one_destination_are_refused() {
        let text = r#"
            [egress.a]
            destinations = ["api.stripe.com"]
            secret.ref = "env://ONE"

            [egress.b]
            destinations = ["api.stripe.com"]
            secret.ref = "env://TWO"
        "#;
        assert!(
            load(text).is_err(),
            "a destination is one credential authority"
        );

        // The same host written with and without its default port is one destination.
        let implicit_port = r#"
            [egress.c]
            destinations = ["api.stripe.com"]
            secret.ref = "env://ONE"

            [egress.d]
            destinations = ["api.stripe.com:443"]
            secret.ref = "env://TWO"
        "#;
        assert!(
            load(implicit_port).is_err(),
            "an implicit :443 must not evade the one-authority rule"
        );
    }

    #[test]
    fn distinct_destinations_are_allowed() {
        let entries = load(
            r#"
            [egress.a]
            destinations = ["api.stripe.com"]
            secret.ref = "env://STRIPE"

            [egress.b]
            destinations = ["api.anthropic.com"]
            secret.ref = "env://ANTHROPIC"
            secret.header = "x-api-key"

            [egress.c]
            destinations = ["api.stripe.com:8443"]
            secret.ref = "env://STRIPE_STAGING"
            "#,
        )
        .expect("distinct destinations are independent");
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn a_header_or_prefix_cannot_forge_a_wire_boundary() {
        for extra in [
            "secret.header = \"X-Bad: injected\"",
            "secret.header = \"X-Bad\\r\\nInjected\"",
            "secret.prefix = \"Bearer \\r\\nX-Injected: y\"",
        ] {
            assert!(
                load(&format!(
                    "[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = \"env://T\"\n{extra}"
                ))
                .is_err(),
                "must refuse {extra}"
            );
        }
    }

    /// `aws://` alone provisions nothing, and that is correct (it signs in-boundary).
    #[test]
    fn only_a_signed_locator_provisions_nothing() {
        let entries =
            load("[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = \"aws://prod\"")
                .expect("valid");
        assert_eq!(
            routes_for(&entries).expect("bindings build")[0].provisioned_name(),
            None,
            "a signed route places nothing in the workload environment: a signature spans \
             several headers, so there is no single location for a placeholder"
        );
    }

    /// A credential scheme the box cannot deliver is refused at `configure`.
    #[test]
    fn an_undeliverable_credential_scheme_is_refused() {
        for locator in [
            "file:///etc/tokens/gh",
            "op://Private/GitHub/token",
            "cmd://mint-a-token",
            "vault://kv/box/key",
        ] {
            let error = load(&format!(
                "[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = {locator:?}"
            ))
            .expect_err(&format!(
                "{locator} cannot be delivered and must be refused"
            ));

            let message = error.to_string();
            assert!(
                message.contains("env://") && message.contains("aws://"),
                "the refusal must name the accepted set: {message}"
            );
        }
    }

    #[test]
    fn a_credential_prefix_carrying_a_brace_is_refused_at_configure() {
        let variable = present_variable();
        for prefix in ["Bearer {}", "{}-", "Token {}=", "a{b", "a}b"] {
            let error = load(&format!(
                "[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = \"env://{variable}\"\nsecret.prefix = {prefix:?}"
            ))
            .expect_err("a brace in the prefix consumes the substitution slot");
            assert!(
                error.to_string().contains("brace"),
                "the refusal names the reason: {error}"
            );
        }
    }

    /// `credential_pattern` is not a key this record accepts.
    #[test]
    fn a_credential_pattern_key_is_not_accepted() {
        let variable = present_variable();
        let parsed: Result<Fixture, _> = toml::from_str(&format!(
            "[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = \"env://{variable}\"\ncredential_pattern = \"/v1/{{}}/models\""
        ));
        assert!(
            parsed.is_err(),
            "credential_pattern is not a key this version accepts"
        );
    }

    /// The placement key accepts the three available values and defaults to `header`.
    #[test]
    fn a_credential_placement_selects_where_the_credential_lands() {
        let variable = present_variable();
        for (placement, extra) in [
            (None, ""),
            (Some("header"), ""),
            (Some("basic_auth"), ""),
            (Some("query_param"), "secret.param = \"api_key\"\n"),
        ] {
            let key = placement
                .map(|p| format!("secret.placement = {p:?}\n"))
                .unwrap_or_default();
            let entries = load(&format!(
                "[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = \"env://{variable}\"\n{key}{extra}"
            ))
            .unwrap_or_else(|error| panic!("{placement:?} must be accepted: {error}"));

            // Every accepted placement builds a route spec through the vault's constructors.
            routes_for(&entries).expect("bindings build")[0]
                .to_route_spec()
                .expect("an accepted placement maps to an inject mode");
        }
    }

    /// `url_path` is refused by name, so its absence reads as withheld not misspelled.
    #[test]
    fn the_url_path_placement_is_refused_as_unavailable() {
        let variable = present_variable();
        let error = load(&format!(
            "[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = \"env://{variable}\"\nsecret.placement = \"url_path\"\n"
        ))
        .expect_err("url_path is not available in this version");

        let message = error.to_string();
        assert!(
            message.contains("not available"),
            "the refusal says it is withheld, not unknown: {message}"
        );
        assert!(
            message.contains("query_param"),
            "and names what to use instead: {message}"
        );
    }

    /// The invalid placement/argument combinations are refused.
    #[test]
    fn an_invalid_placement_combination_is_refused() {
        let variable = present_variable();
        for (extra, why) in [
            ("secret.placement = \"cookie\"\n", "an unknown placement"),
            (
                "secret.placement = \"query_param\"\n",
                "query_param without credential_param",
            ),
            (
                "secret.placement = \"query_param\"\nsecret.param = \"\"\n",
                "an empty parameter name",
            ),
            (
                "secret.placement = \"query_param\"\nsecret.param = \"a&b\"\n",
                "a parameter name that would split on the wire",
            ),
            (
                "secret.placement = \"query_param\"\nsecret.param = \"k\"\nsecret.header = \"x-api-key\"\n",
                "a header name beside a non-header placement",
            ),
            (
                "secret.placement = \"basic_auth\"\nsecret.prefix = \"Bearer \"\n",
                "a prefix beside a non-header placement",
            ),
            (
                "secret.param = \"api_key\"\n",
                "credential_param without the placement that uses it",
            ),
        ] {
            assert!(
                load(&format!(
                    "[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = \"env://{variable}\"\n{extra}"
                ))
                .is_err(),
                "{why} must be refused"
            );
        }
    }

    /// The two deliverable schemes still load.
    #[test]
    fn a_deliverable_credential_scheme_is_accepted() {
        let variable = present_variable();
        for locator in [format!("env://{variable}"), "aws://prod".to_string()] {
            load(&format!(
                "[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = {locator:?}"
            ))
            .unwrap_or_else(|error| panic!("{locator} must be accepted: {error}"));
        }
    }

    /// A reserved or unset variable is refused when the binding is built, not when the
    /// file parses: the TOML is well-formed, but the box sets `PATH` itself and an unset
    /// variable would mint a phantom standing in for nothing.
    #[test]
    fn a_credential_may_not_claim_a_reserved_or_unset_variable() {
        for (name, expected) in [
            ("PATH", "reserved"),
            ("HTTPS_PROXY", "reserved"),
            ("LD_PRELOAD", "reserved"),
            ("1TOKEN", "invalid"),
            ("STRANDS_BOX_DEFINITELY_UNSET_VARIABLE", "is not set"),
        ] {
            let entries = load(&format!(
                "[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = \"env://{name}\""
            ))
            .expect("the file itself is valid");

            // `EgressRoute` holds a locator and implements no `Debug`; match rather
            // than `expect_err`.
            let error = match routes_for(&entries) {
                Ok(_) => panic!("{name} must be refused as a phantom target"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(expected),
                "error for {name} must mention {expected:?}: {error}"
            );
        }
    }

    /// A variable holding only whitespace is refused too, not just an unset one.
    #[test]
    fn a_credential_variable_holding_only_whitespace_is_refused() {
        let name = "STRANDS_BOX_WHITESPACE_ONLY_CREDENTIAL";
        for spelling in [" ", "   ", "\n", "\t "] {
            // SAFETY (test): the name is scoped to this test, so nothing else reads or writes it.
            unsafe { std::env::set_var(name, spelling) };

            let entries = load(&format!(
                "[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = \"env://{name}\""
            ))
            .expect("the file itself is valid");

            let error = match routes_for(&entries) {
                Ok(_) => panic!("{spelling:?} must be refused as a phantom target"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("whitespace"),
                "error for {spelling:?} must name the reason: {error}"
            );
        }

        // SAFETY (test): as above.
        unsafe { std::env::remove_var(name) };
    }

    // --- credsd source: type inferred from the daemon, no secret.type key ---

    /// A credsd signed route provisions nothing in the workload environment.
    #[test]
    fn a_credsd_route_provisions_nothing() {
        let entries = load(
            r#"
            [egress.a]
            destinations = ["bedrock-runtime.us-west-2.amazonaws.com"]
            secret.ref = "credsd://prod-inference"
            "#,
        )
        .expect("valid");
        assert_eq!(
            routes_for(&entries).expect("bindings build")[0].provisioned_name(),
            None,
            "a credsd route signs in-boundary, so it places no phantom"
        );
    }

    /// A `credsd://` source is accepted and opens a signed route with no declared type.
    /// The daemon's `material.type` picks the signer per request, so the box needs no type key.
    #[test]
    fn a_credsd_source_is_inferred_and_signs() {
        let entries = load(
            r#"
            [egress.a]
            destinations = ["bedrock-runtime.us-west-2.amazonaws.com"]
            secret.ref = "credsd://prod"
            "#,
        )
        .expect("a credsd source infers its type at request time");
        let secret = entries["a"].secret.as_ref().expect("secret");
        assert!(
            EgressEntry::signs_in_boundary(secret),
            "a credsd route signs in-boundary"
        );
        routes_for(&entries).expect("bindings build")[0]
            .to_route_spec()
            .expect("a credsd entry maps to a signed route");
    }

    /// `secret.type` is not a key the box carries, so `deny_unknown_fields` refuses it as an
    /// unknown field on every scheme — the type comes from the daemon, never from config.
    #[test]
    fn a_secret_type_key_is_rejected_on_every_scheme() {
        for reference in ["credsd://prod", "env://TOKEN", "aws://prod"] {
            let text = format!(
                "[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = {reference:?}\nsecret.type = \"aws\"\n"
            );
            let error = match toml::from_str::<Fixture>(&text) {
                Ok(_) => panic!("{reference}: secret.type must be refused as an unknown key"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("type"),
                "{reference}: the refusal names the unknown key: {error}"
            );
        }
    }

    /// A `credsd://` reference with an empty environment is refused.
    #[test]
    fn a_credsd_source_with_an_empty_environment_is_refused() {
        let error = load(
            r#"
            [egress.a]
            destinations = ["api.test"]
            secret.ref = "credsd://"
            "#,
        )
        .expect_err("an empty environment names nothing");
        assert!(error.to_string().contains("environment"), "{error}");
    }

    /// An `env://` entry with no other keys defaults to a bearer `Authorization` header.
    #[test]
    fn an_env_entry_defaults_to_a_bearer_header() {
        let entries = load(
            r#"
            [egress.a]
            destinations = ["api.stripe.com"]
            secret.ref = "env://TOKEN"
            "#,
        )
        .expect("an env entry with only a ref is valid");
        let secret = entries["a"].secret.as_ref().expect("secret");
        assert_eq!(
            EgressEntry::placement(secret),
            Placement::Header {
                name: "Authorization".to_string(),
                prefix: "Bearer ".to_string(),
            }
        );
    }

    /// The preflight's environment set is every distinct `credsd://` environment, in order — and it
    /// ignores `env://` and `aws://` sources, which name no credsd environment.
    #[test]
    fn credsd_environments_are_the_distinct_credsd_sources() {
        let entries = load(
            r#"
            [egress.bedrock]
            destinations = ["bedrock-runtime.us-west-2.amazonaws.com"]
            secret.ref = "credsd://prod-inference"

            [egress.also_prod]
            destinations = ["bedrock-runtime.us-east-1.amazonaws.com"]
            secret.ref = "credsd://prod-inference"

            [egress.staging]
            destinations = ["bedrock-runtime.eu-west-1.amazonaws.com"]
            secret.ref = "credsd://staging"

            [egress.stripe]
            destinations = ["api.stripe.com"]
            secret.ref = "env://STRIPE"
            "#,
        )
        .expect("valid");

        assert_eq!(
            credsd_environments(&entries, &BTreeMap::new()),
            vec!["prod-inference", "staging"],
            "each credsd environment appears once, in declaration order, and env:// is ignored"
        );
    }

    /// A credsd source declared only on a remote MCP server lands in `record.remote_mcp`, not
    /// `record.egress`. `credsd_environments` takes both maps by construction, so the source is still
    /// covered — keying the preflight to egress alone (an earlier bug) deferred a down daemon to the
    /// first `mcp:call` instead of failing at box start.
    #[test]
    fn credsd_environments_covers_the_remote_mcp_map() {
        let egress = load(
            r#"
            [egress.stripe]
            destinations = ["api.stripe.com"]
            secret.ref = "env://STRIPE"
            "#,
        )
        .expect("valid");
        let remote_mcp = load(
            r#"
            [egress.remote_bedrock]
            protocol = "mcp"
            destinations = ["bedrock-runtime.us-west-2.amazonaws.com"]
            secret.ref = "credsd://prod-inference"
            "#,
        )
        .expect("valid");

        assert!(
            credsd_environments(&egress, &BTreeMap::new()).is_empty(),
            "the credsd source is not in egress, so egress alone names no environment"
        );
        assert_eq!(
            credsd_environments(&egress, &remote_mcp),
            vec!["prod-inference"],
            "walking both maps covers a credsd source declared only on a remote MCP server"
        );
    }

    /// A box with no credsd source names no environment, so the preflight contacts no daemon.
    #[test]
    fn a_box_with_no_credsd_source_names_no_environment() {
        let entries = load(
            r#"
            [egress.stripe]
            destinations = ["api.stripe.com"]
            secret.ref = "env://STRIPE"
            "#,
        )
        .expect("valid");
        assert!(credsd_environments(&entries, &BTreeMap::new()).is_empty());
    }

    /// A credsd credential signs in-boundary, so it refuses header/prefix/placement/param.
    #[test]
    fn a_credsd_source_refuses_placement_keys() {
        for extra in [
            "secret.header = \"x-api-key\"",
            "secret.prefix = \"Bearer \"",
            "secret.placement = \"basic_auth\"",
            "secret.param = \"key\"",
        ] {
            let error = load(&format!(
                "[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = \"credsd://prod\"\n{extra}"
            ))
            .expect_err(&format!("a credsd route must refuse {extra}"));
            assert!(
                error.to_string().contains("signed"),
                "the refusal says it signs in-boundary: {error}"
            );
        }
    }
}
