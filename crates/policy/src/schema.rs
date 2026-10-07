//! The shipped `.cedarschema` and the `Request` -> Cedar tuple mapping
//! (docs/design/decisions.md#the-action-vocabulary-is-closed-and-strict-validated-at-load).

use std::{borrow::Cow, collections::HashSet, sync::OnceLock};

use cedar_policy::{
    Context, EntityId, EntityTypeName, EntityUid, Request as CedarRequest, RestrictedExpression,
    Schema,
};

use crate::Principal;
use crate::error::PolicyError;
use crate::request::{DEFAULT_PRINCIPAL_ID, FsOperation, Request};

const BOX_NAMESPACE: &str = "Box";
const FIXED_ACTION_TYPE: &str = "Box::Action";

/// The shipped Cedar schema source — the fixed action vocabulary. Embedded at
/// build time so the crate carries its own schema with no filesystem dependency.
pub(crate) const SCHEMA_SRC: &str = include_str!("../schema/actions.cedarschema");

/// The effective action schema used for policy validation and request binding.
pub(crate) struct ActionSchema {
    pub(crate) source: String,
    pub(crate) cedar: Schema,
    pub(crate) tool_actions: HashSet<EntityUid>,
}

/// Compose the canonical schema with ordered MCP schema fragments.
pub(crate) fn action_schema(mcp_schemas: &[String]) -> Result<ActionSchema, PolicyError> {
    for fragment in mcp_schemas {
        crate::mcp_schema::validate_unbound_mcp_schema(fragment)
            .map_err(|error| PolicyError::Schema(error.to_string()))?;
    }
    let mut source = SCHEMA_SRC.to_string();
    for fragment in mcp_schemas {
        let base = source.trim_end();
        source = format!("{base}\n{fragment}");
    }
    let (cedar, warnings) = Schema::from_cedarschema_str(&source)
        .map_err(|error| PolicyError::Schema(error.to_string()))?;
    let warnings = warnings
        .map(|warning| warning.to_string())
        .collect::<Vec<_>>();
    if !warnings.is_empty() {
        return Err(PolicyError::Schema(warnings.join("; ")));
    }
    let tool_actions = cedar
        .actions()
        .filter(|action| {
            action.type_name().basename() == "Action"
                && action.type_name().namespace_components().next().is_some()
                && action.type_name().to_string() != FIXED_ACTION_TYPE
        })
        .cloned()
        .collect();
    Ok(ActionSchema {
        source,
        cedar,
        tool_actions,
    })
}

/// The sole Cedar principal type.
pub(crate) const AGENT_TYPE: &str = "Box::Agent";

/// The Cedar resource type required by the action schema.
pub(crate) const RESOURCE_TYPE: &str = "Box::Resource";

/// The enum entity type carrying the exact kernel verb on `fs:read`. Per-action enums,
/// so a verb the enum does not declare is a load error, not a silent non-match.
pub(crate) const FS_READ_OPERATION_TYPE: &str = "Box::FsReadOperation";
/// The enum entity type carrying the exact kernel verb on `fs:write`.
pub(crate) const FS_WRITE_OPERATION_TYPE: &str = "Box::FsWriteOperation";
/// The enum entity type carrying the exact kernel verb on `fs:delete`.
pub(crate) const FS_DELETE_OPERATION_TYPE: &str = "Box::FsDeleteOperation";
/// The enum entity type carrying the exact kernel verb on `fs:move`.
pub(crate) const FS_MOVE_OPERATION_TYPE: &str = "Box::FsMoveOperation";
/// The enum entity type carrying the exact kernel verb on `fs:other`.
pub(crate) const FS_OTHER_OPERATION_TYPE: &str = "Box::FsOtherOperation";
/// The enum entity type carrying how an effect ended, on the `output` of every
/// filesystem response event.
pub(crate) const FS_RESPONSE_RESULT_TYPE: &str = "Box::FsResponseResult";

/// The fixed resource id. The resource carries no policy information.
pub(crate) const UNUSED_RESOURCE_ID: &str = "unused";

/// The action-id strings used by request mapping. Four filesystem verbs at customer
/// altitude, plus a fail-closed catch-all; the kernel's exact verb rides
/// `context.input.operation`
/// (docs/design/decisions.md#filesystem-authorization-uses-four-verbs-and-a-catch-all).
pub(crate) mod action {
    /// `fs:read` — read content or metadata, enumerate, read a link, change directory,
    /// or test executability.
    pub(crate) const FS_READ: &str = "fs:read";
    /// `fs:write` — write content, create a directory, change permissions, or create a
    /// symlink.
    pub(crate) const FS_WRITE: &str = "fs:write";
    /// `fs:delete` — remove a file or directory.
    pub(crate) const FS_DELETE: &str = "fs:delete";
    /// `fs:move` — rename or move a path.
    pub(crate) const FS_MOVE: &str = "fs:move";
    /// `fs:other` — an operation the four verbs do not name. A rule reaches it only by
    /// naming `fs:other`, so an unmapped verb never inherits a read/write/delete/move
    /// permit.
    pub(crate) const FS_OTHER: &str = "fs:other";
    /// `net:connect` — L4 TCP connect (the durable floor).
    pub(crate) const NET_CONNECT: &str = "net:connect";
    /// `http:request` — the L7 HTTP decision; its one `::response` carries the reply's `status`.
    pub(crate) const HTTP_REQUEST: &str = "http:request";
    /// `mcp:call` — one tool call on a connected MCP server.
    pub(crate) const MCP_CALL: &str = "mcp:call";
    /// `shell:exec` — a resolved command line whose program the Shell implements.
    pub(crate) const SHELL_EXEC: &str = "shell:exec";
    /// `shell:spawn` — a resolved command line handed to a host binary.
    pub(crate) const SHELL_SPAWN: &str = "shell:spawn";
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ActionIdentity {
    Fixed { id: &'static str },
    McpTool { namespace: String, tool: String },
}

impl ActionIdentity {
    pub(crate) fn for_request(request: &Request<'_>) -> Self {
        match request {
            Request::McpCall {
                server,
                tool: Some(tool),
                arguments: Some(_),
                ..
            } => Self::mcp_tool(server, tool),
            other => Self::Fixed {
                id: action_id(other),
            },
        }
    }

    pub(crate) fn mcp_tool(server: &str, tool: &str) -> Self {
        Self::McpTool {
            namespace: mcp_action_namespace(server),
            tool: tool.to_string(),
        }
    }

    pub(crate) fn cedar_uid(&self) -> Result<EntityUid, PolicyError> {
        match self {
            Self::Fixed { id } => fixed_action_uid(id),
            Self::McpTool { namespace, tool } => {
                let action_type = format!("{namespace}::Action")
                    .parse::<EntityTypeName>()
                    .map_err(|error| PolicyError::Schema(error.to_string()))?;
                Ok(EntityUid::from_type_name_and_id(
                    action_type,
                    EntityId::new(tool),
                ))
            }
        }
    }

    pub(crate) fn observer_action(&self) -> Cow<'_, str> {
        match self {
            Self::Fixed { id } => Cow::Owned(format!(
                "{FIXED_ACTION_TYPE}::\"{}\"",
                EntityId::new(id).escaped()
            )),
            Self::McpTool { namespace, tool } => Cow::Owned(format!(
                "{namespace}::Action::\"{}\"",
                EntityId::new(tool).escaped()
            )),
        }
    }
}

pub(crate) fn mcp_action_namespace(server: &str) -> String {
    cedar_identifier(server)
}

pub(crate) fn cedar_identifier(raw: &str) -> String {
    let mut identifier = String::with_capacity(raw.len() + 1);
    for character in raw.chars() {
        identifier.push(if character.is_ascii_alphanumeric() || character == '_' {
            character
        } else {
            '_'
        });
    }
    if identifier.as_bytes().first().is_none_or(u8::is_ascii_digit) {
        identifier.insert(0, '_');
    }
    if matches!(
        identifier.as_str(),
        "true" | "false" | "if" | "then" | "else" | "in" | "is" | "like" | "has" | "__cedar"
    ) {
        identifier.push('_');
    }
    identifier
}

/// The coarse filesystem action id for one operation.
///
/// The kernel's exact verb still rides `context.input.operation`; this maps that verb to
/// the customer-altitude action a rule names. `ExecFile` folds into `fs:read` because the
/// executability probe is a metadata disclosure, not an execution — running a program is a
/// shell decision.
pub(crate) fn fs_action_id(operation: FsOperation) -> &'static str {
    match operation {
        FsOperation::ReadContent
        | FsOperation::ReadMetadata
        | FsOperation::Enumerate
        | FsOperation::ReadLink
        | FsOperation::ChangeDir
        | FsOperation::ExecFile => action::FS_READ,
        FsOperation::WriteContent
        | FsOperation::CreateDir
        | FsOperation::SetPermissions
        | FsOperation::Symlink => action::FS_WRITE,
        FsOperation::RemoveFile | FsOperation::RemoveDir => action::FS_DELETE,
        FsOperation::Rename => action::FS_MOVE,
        FsOperation::Other => action::FS_OTHER,
    }
}

/// The `context.*` attribute-name strings used by [`context_for`].
pub(crate) mod attr {
    /// `context.input.path` — filesystem path (`fs:*`).
    pub(crate) const PATH: &str = "path";
    /// `context.input.operation` — the exact kernel operation, on every `fs:*` action.
    pub(crate) const OPERATION: &str = "operation";
    /// `output.result` — how an effect ended, on every filesystem response event.
    pub(crate) const RESULT: &str = "result";
    /// `context.input.host` — destination host (`net:*`).
    pub(crate) const HOST: &str = "host";
    /// `context.input.port` — destination port (`net:*`).
    pub(crate) const PORT: &str = "port";
    /// `context.input.ip` — optional pinned destination IP (`net:connect`).
    pub(crate) const IP: &str = "ip";
    /// `context.input.method` — HTTP method (`http:request`).
    pub(crate) const METHOD: &str = "method";
    /// `output.status` — the upstream's reply status on an `http:request` response event, and
    /// the exit status on a `shell:exec` or `shell:spawn` response event.
    pub(crate) const STATUS: &str = "status";
    /// `context.input.body_bytes` — HTTP body length (`http:request`).
    pub(crate) const BODY_BYTES: &str = "body_bytes";
    /// `context.input.intercepted` — whether HTTP was seen through TLS interception.
    pub(crate) const INTERCEPTED: &str = "intercepted";
    /// `context.input.server` — the MCP server a tool call names (`mcp:call`).
    pub(crate) const SERVER: &str = "server";
    /// `context.input.tool` — the tool a `tools/call` names (`mcp:call`).
    pub(crate) const TOOL: &str = "tool";
    /// `context.input.prompt` — the prompt a `prompts/get` names (`mcp:call`).
    pub(crate) const PROMPT: &str = "prompt";
    /// `context.input.uri` — the resource a `resources/read` names (`mcp:call`).
    pub(crate) const URI: &str = "uri";
    /// `context.input.command` — the submitted command text (every `shell:*` action).
    pub(crate) const COMMAND: &str = "command";
    /// `context.input.program` — the resolved program (`shell:exec`, `shell:spawn`).
    pub(crate) const PROGRAM: &str = "program";
    /// `context.input.program_path` — the resolved binary path (`shell:spawn`).
    ///
    /// Deliberately not `path`: that name already means a filesystem path on `fs:*` and a
    /// URL path on `http:request`/`net:response`, and the collision already caused a
    /// measured over-denial.
    pub(crate) const PROGRAM_PATH: &str = "program_path";
    /// `context.input.credential_reads` — exact credential paths exposed to one leaf.
    pub(crate) const CREDENTIAL_READS: &str = "credential_reads";
    /// `context.input.arg1` — first argument after the program (`shell:exec`, `shell:spawn`).
    pub(crate) const ARG1: &str = "arg1";
    /// `context.input.arg2` — second argument after the program.
    pub(crate) const ARG2: &str = "arg2";
    /// `context.input.arg_count` — how many arguments follow the program.
    pub(crate) const ARG_COUNT: &str = "arg_count";
    /// `context.cwd` — the working directory the command line runs in.
    pub(crate) const CWD: &str = "cwd";
}

/// Parse and cache the shipped schema. Parsing is infallible in practice (the schema
/// is a shipped constant, validated by a crate test), but a parse fault surfaces as a
/// [`PolicyError::Schema`] rather than a panic so the load path stays fail-closed.
#[cfg(test)]
pub(crate) fn schema() -> Result<&'static Schema, PolicyError> {
    static SCHEMA: OnceLock<Result<Schema, String>> = OnceLock::new();
    SCHEMA
        .get_or_init(|| {
            Schema::from_cedarschema_str(SCHEMA_SRC)
                .map(|(s, _warnings)| s)
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| PolicyError::Schema(e.clone()))
}

/// Parse and cache one entity UID whose type and id are both fixed strings.
fn cached_uid(
    cell: &'static OnceLock<Result<EntityUid, String>>,
    entity_type: &str,
    entity_id: &str,
) -> Result<EntityUid, PolicyError> {
    cell.get_or_init(|| {
        entity_type
            .parse::<EntityTypeName>()
            .map(|parsed| EntityUid::from_type_name_and_id(parsed, EntityId::new(entity_id)))
            .map_err(|error| error.to_string())
    })
    .clone()
    .map_err(PolicyError::Schema)
}

/// The fixed principal UID.
fn principal_uid(_principal: &Principal) -> Result<EntityUid, PolicyError> {
    static AGENT: OnceLock<Result<EntityUid, String>> = OnceLock::new();
    cached_uid(&AGENT, AGENT_TYPE, DEFAULT_PRINCIPAL_ID)
}

/// The fixed resource UID.
fn resource_uid() -> Result<EntityUid, PolicyError> {
    static RESOURCE: OnceLock<Result<EntityUid, String>> = OnceLock::new();
    cached_uid(&RESOURCE, RESOURCE_TYPE, UNUSED_RESOURCE_ID)
}

/// The per-action operation entity for `context.input.operation`: the enum type its
/// action declares, and the verb.
pub(crate) fn fs_operation_entity(operation: FsOperation) -> (&'static str, &'static str) {
    let entity_type = match fs_action_id(operation) {
        action::FS_READ => FS_READ_OPERATION_TYPE,
        action::FS_WRITE => FS_WRITE_OPERATION_TYPE,
        action::FS_DELETE => FS_DELETE_OPERATION_TYPE,
        action::FS_MOVE => FS_MOVE_OPERATION_TYPE,
        _ => FS_OTHER_OPERATION_TYPE,
    };
    (entity_type, operation.as_str())
}

/// The operation entity value for one kernel verb. The type names parse once; the eid
/// comes from the closed [`FsOperation::as_str`] set, so it always names a declared
/// enum value.
fn fs_operation_expr(operation: FsOperation) -> Result<RestrictedExpression, PolicyError> {
    static TYPE_NAMES: OnceLock<Result<Vec<(&'static str, EntityTypeName)>, String>> =
        OnceLock::new();
    let (entity_type, verb) = fs_operation_entity(operation);
    let type_names = TYPE_NAMES
        .get_or_init(|| {
            [
                FS_READ_OPERATION_TYPE,
                FS_WRITE_OPERATION_TYPE,
                FS_DELETE_OPERATION_TYPE,
                FS_MOVE_OPERATION_TYPE,
                FS_OTHER_OPERATION_TYPE,
            ]
            .into_iter()
            .map(|name| {
                name.parse::<EntityTypeName>()
                    .map(|parsed| (name, parsed))
                    .map_err(|error| error.to_string())
            })
            .collect()
        })
        .as_ref()
        .map_err(|error| PolicyError::Schema(error.clone()))?;
    let type_name = type_names
        .iter()
        .find(|(name, _)| *name == entity_type)
        .map(|(_, parsed)| parsed)
        .ok_or_else(|| PolicyError::Schema(format!("unknown operation type: {entity_type}")))?;
    Ok(RestrictedExpression::new_entity_uid(
        EntityUid::from_type_name_and_id(type_name.clone(), EntityId::new(verb)),
    ))
}

/// The cached action UID for one fixed action-id string.
fn fixed_action_uid(id: &str) -> Result<EntityUid, PolicyError> {
    static ACTIONS: OnceLock<Result<Vec<EntityUid>, String>> = OnceLock::new();

    let uids = ACTIONS
        .get_or_init(|| {
            ACTION_IDS
                .iter()
                .map(|id| {
                    format!("{BOX_NAMESPACE}::Action::\"{id}\"")
                        .parse::<EntityUid>()
                        .map_err(|error| error.to_string())
                })
                .collect()
        })
        .as_ref()
        .map_err(|error| PolicyError::Schema(format!("bad action uid: {error}")))?;

    if let Some(index) = ACTION_IDS.iter().position(|candidate| *candidate == id) {
        return uids
            .get(index)
            .cloned()
            .ok_or_else(|| PolicyError::Schema(format!("unknown action id: {id}")));
    }
    Err(PolicyError::Schema(format!("unknown action id: {id}")))
}

/// Every action id, in one place, so the cached UIDs cover exactly the closed set
/// [`action_id`] can return. The nine actions the box raises: five filesystem verbs,
/// two network decisions, and two shell command decisions. The schema has no group
/// actions, so every id here is one a request names directly.
///
/// **There is no response action.** The response leg is `http:request`'s response phase: it
/// records what came back and takes no decision, so it names no action of its own.
const ACTION_IDS: &[&str] = &[
    action::FS_READ,
    action::FS_WRITE,
    action::FS_DELETE,
    action::FS_MOVE,
    action::FS_OTHER,
    action::NET_CONNECT,
    action::HTTP_REQUEST,
    action::SHELL_EXEC,
    action::SHELL_SPAWN,
    action::MCP_CALL,
];

/// The Cedar action-id string for a [`Request`] variant. This is the single
/// place a variant maps to a verb; the schema declares the same strings.
pub(crate) fn action_id(req: &Request<'_>) -> &'static str {
    match req {
        Request::Fs { operation, .. } => fs_action_id(*operation),
        Request::Connect { .. } => action::NET_CONNECT,
        Request::Http { .. } => action::HTTP_REQUEST,
        Request::ShellExec { .. } => action::SHELL_EXEC,
        // A tool call with arguments uses [`ActionIdentity::McpTool`].
        Request::McpCall { .. } => action::MCP_CALL,
        Request::ShellSpawn { .. } => action::SHELL_SPAWN,
    }
}

/// The `arg1`/`arg2`/`arg_count` fields shared by `shell:exec` and `shell:spawn`.
///
/// One helper for both, so the two actions cannot disagree about which position `arg1`
/// names. `arg1` and `arg2` are optional in the schema and are pushed only when the
/// argument exists, matching how the `fs:*` flags ride only the operations that declare
/// them.
fn argument_fields(args: &[String]) -> Vec<(String, RestrictedExpression)> {
    let mut fields = vec![(
        attr::ARG_COUNT.to_string(),
        RestrictedExpression::new_long(crate::request::arg_count(args)),
    )];
    for (name, value) in [(attr::ARG1, args.first()), (attr::ARG2, args.get(1))] {
        if let Some(value) = value {
            fields.push((
                name.to_string(),
                RestrictedExpression::new_string(value.clone()),
            ));
        }
    }
    fields
}

fn credential_read_field(paths: &[String]) -> Option<(String, RestrictedExpression)> {
    (!paths.is_empty()).then(|| {
        (
            attr::CREDENTIAL_READS.to_string(),
            RestrictedExpression::new_set(
                paths.iter().cloned().map(RestrictedExpression::new_string),
            ),
        )
    })
}

/// Build the `context` record for a [`Request`], grouped under `input`. Every
/// discriminating field lives here, never on the resource.
///
/// **The `input` group is required by the engine.** The temporal extension derives an
/// event's declared fields from the action's `input` record and from nothing else, so a flat
/// `context` leaves every temporal predicate with no fields and a hard load error.
fn context_for(
    req: &Request<'_>,
    schema: &Schema,
    action: &EntityUid,
) -> Result<Context, PolicyError> {
    // A per-tool `tools/call` carries its raw JSON arguments. Cedar types them against the
    // generated action input schema.
    if let Request::McpCall {
        arguments: Some(arguments),
        ..
    } = req
    {
        let input = serde_json::json!({ "input": arguments });
        return Context::from_json_value(input, Some((schema, action)))
            .map_err(|error| PolicyError::Schema(format!("invalid MCP tool arguments: {error}")));
    }
    let input: Vec<(String, RestrictedExpression)> = match req {
        Request::Fs {
            path, operation, ..
        } => {
            let mut fields = vec![(
                attr::PATH.to_string(),
                RestrictedExpression::new_string(path.reported().into_owned()),
            )];
            fields.push((attr::OPERATION.to_string(), fs_operation_expr(*operation)?));
            fields
        }
        Request::Connect { host, ip, port } => {
            let mut fields = vec![
                (
                    attr::HOST.to_string(),
                    RestrictedExpression::new_string((*host).to_string()),
                ),
                (
                    attr::PORT.to_string(),
                    RestrictedExpression::new_long(i64::from(*port)),
                ),
            ];
            // `ip?` is optional in the schema — only include it when the PEP pinned one.
            if let Some(ip) = ip {
                fields.push((
                    attr::IP.to_string(),
                    RestrictedExpression::new_string(crate::address::canonical(*ip)),
                ));
            }
            fields
        }
        Request::Http {
            host,
            port,
            method,
            path,
            body_bytes,
            intercepted,
        } => vec![
            (
                attr::HOST.to_string(),
                RestrictedExpression::new_string((*host).to_string()),
            ),
            (
                attr::PORT.to_string(),
                RestrictedExpression::new_long(i64::from(*port)),
            ),
            (
                attr::METHOD.to_string(),
                RestrictedExpression::new_string((*method).to_string()),
            ),
            (
                attr::PATH.to_string(),
                RestrictedExpression::new_string((*path).to_string()),
            ),
            (
                attr::BODY_BYTES.to_string(),
                RestrictedExpression::new_long(usize_to_cedar_long(*body_bytes)?),
            ),
            (
                attr::INTERCEPTED.to_string(),
                RestrictedExpression::new_bool(*intercepted),
            ),
        ],
        Request::McpCall {
            server,
            method,
            tool,
            prompt,
            uri,
            ..
        } => {
            // The coarse `mcp:call` context (`arguments: None`). `server` and `method` are on every
            // frame. The per-item identity is optional in the schema and present only for the method
            // that carries it, so a rule that reads `context.input.tool` guards on `has tool`.
            let mut fields = vec![
                (
                    attr::SERVER.to_string(),
                    RestrictedExpression::new_string((*server).to_string()),
                ),
                (
                    attr::METHOD.to_string(),
                    RestrictedExpression::new_string((*method).to_string()),
                ),
            ];
            for (name, value) in [(attr::TOOL, tool), (attr::PROMPT, prompt), (attr::URI, uri)] {
                if let Some(value) = value {
                    fields.push((
                        name.to_string(),
                        RestrictedExpression::new_string((*value).to_string()),
                    ));
                }
            }
            fields
        }
        Request::ShellExec {
            command,
            program,
            args,
            cwd,
        } => {
            let mut fields = vec![
                (
                    attr::COMMAND.to_string(),
                    RestrictedExpression::new_string((*command).to_string()),
                ),
                (
                    attr::PROGRAM.to_string(),
                    RestrictedExpression::new_string((*program).to_string()),
                ),
                (
                    attr::CWD.to_string(),
                    RestrictedExpression::new_string((*cwd).to_string()),
                ),
            ];
            fields.extend(argument_fields(args));
            fields
        }
        Request::ShellSpawn {
            command,
            program,
            program_path,
            credential_reads,
            args,
            cwd,
        } => {
            let mut fields = vec![
                (
                    attr::COMMAND.to_string(),
                    RestrictedExpression::new_string((*command).to_string()),
                ),
                (
                    attr::PROGRAM.to_string(),
                    RestrictedExpression::new_string((*program).to_string()),
                ),
                (
                    attr::PROGRAM_PATH.to_string(),
                    RestrictedExpression::new_string((*program_path).to_string()),
                ),
                (
                    attr::CWD.to_string(),
                    RestrictedExpression::new_string((*cwd).to_string()),
                ),
            ];
            fields.extend(credential_read_field(credential_reads));
            fields.extend(argument_fields(args));
            fields
        }
    };

    let input_record = RestrictedExpression::new_record(input)
        .map_err(|e| PolicyError::Schema(format!("failed to build context.input: {e}")))?;
    Context::from_pairs([("input".to_string(), input_record)])
        .map_err(|e| PolicyError::Schema(format!("failed to build context: {e}")))
}

fn usize_to_cedar_long(value: usize) -> Result<i64, PolicyError> {
    i64::try_from(value)
        .map_err(|_| PolicyError::Schema("HTTP body length exceeds Cedar Long".to_string()))
}

/// Build a schema-bound Cedar authorization request from a [`Request`].
pub(crate) fn to_cedar_request(
    principal: &Principal,
    req: &Request<'_>,
    identity: &ActionIdentity,
    schema: &Schema,
) -> Result<CedarRequest, PolicyError> {
    let principal = principal_uid(principal)?;
    let action = identity.cedar_uid()?;
    let resource = resource_uid()?;
    let context = context_for(req, schema, &action)?;
    // The schema is bound: a non-conforming request errors here rather than silently
    // no-matching.
    CedarRequest::new(principal, action, resource, context, Some(schema))
        .map_err(|e| PolicyError::Schema(format!("request does not conform to schema: {e}")))
}

/// Run Strict validation against the shipped schema at load. Called by the
/// store's compose path; a fault aborts startup.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_schema_parses() {
        assert!(schema().is_ok());
    }

    #[test]
    fn a_per_tool_action_uses_the_normalized_server_namespace() {
        assert_eq!(mcp_action_namespace("Github"), "Github");
        assert_eq!(mcp_action_namespace("7-demo"), "_7_demo");
        assert_eq!(mcp_action_namespace("if"), "if_");
        let identity = ActionIdentity::mcp_tool("issues-mcp", "SearchIssues");
        assert_eq!(
            identity.observer_action().as_ref(),
            r#"issues_mcp::Action::"SearchIssues""#
        );
        assert_eq!(
            identity.cedar_uid().expect("tool uid").to_string(),
            r#"issues_mcp::Action::"SearchIssues""#
        );
        let escaped = ActionIdentity::mcp_tool("issues-mcp", "read.\"wiki\":item");
        assert_eq!(
            escaped.observer_action().as_ref(),
            r#"issues_mcp::Action::"read.\"wiki\":item""#
        );
        assert_eq!(
            escaped.cedar_uid().expect("escaped tool uid").to_string(),
            escaped.observer_action()
        );
        assert_eq!(
            ActionIdentity::Fixed {
                id: action::FS_READ
            }
            .cedar_uid()
            .expect("fixed uid")
            .to_string(),
            r#"Box::Action::"fs:read""#
        );
        assert_eq!(
            ActionIdentity::Fixed {
                id: action::FS_READ
            }
            .observer_action(),
            r#"Box::Action::"fs:read""#
        );
    }

    #[test]
    fn to_cedar_request_binds_schema_for_all_variants() {
        // Every request builds against the bound schema.
        let approved = crate::path::ApprovedPath::interpreter_resolved("/tmp/x");
        let reqs = [
            Request::Fs {
                path: &approved,
                operation: crate::request::FsOperation::ReadContent,
            },
            Request::Connect {
                host: "h",
                ip: None,
                port: 443,
            },
            Request::Http {
                host: "h",
                port: 443,
                method: "GET",
                path: "/",
                body_bytes: 12,
                intercepted: true,
            },
            // Two arguments, so both optional positions are exercised.
            Request::ShellExec {
                command: "rm -rf /tmp/x",
                program: "rm",
                args: &["-rf".to_string(), "/tmp/x".to_string()],
                cwd: "/workspace",
            },
            // No arguments, so `arg1`/`arg2` are absent. A closed record makes an
            // *omitted* optional field legal and a *present unknown* field a hard error,
            // so this direction is the one worth pinning.
            Request::ShellExec {
                command: "pwd",
                program: "pwd",
                args: &[],
                cwd: "/workspace",
            },
            Request::ShellSpawn {
                command: "git push origin main",
                program: "git",
                program_path: "/usr/bin/git",
                credential_reads: &[],
                args: &["push".to_string(), "origin".to_string(), "main".to_string()],
                cwd: "/workspace/repo",
            },
        ];
        // One principal for every action now, which is the point: the action says which
        // boundary can raise it, so the principal no longer selects one.
        let principal = Principal::agent();
        let schema = schema().expect("shipped schema");
        for r in &reqs {
            let identity = ActionIdentity::for_request(r);
            assert!(
                to_cedar_request(&principal, r, &identity, schema).is_ok(),
                "failed to map {r:?}"
            );
        }
    }

    /// Integration metadata does not change the fixed policy principal.
    #[test]
    fn every_integration_principal_maps_to_agent_self() {
        let approved = crate::path::ApprovedPath::interpreter_resolved("/workspace/main.py");
        let request = Request::Fs {
            path: &approved,
            operation: crate::request::FsOperation::ReadContent,
        };
        let schema = schema().expect("shipped schema");
        let identity = ActionIdentity::for_request(&request);

        let default_uid = to_cedar_request(&Principal::agent(), &request, &identity, schema)
            .expect("default principal maps")
            .principal()
            .expect("principal is present")
            .to_string();
        let named_uid = to_cedar_request(
            &Principal::agent().with_id("worker-1"),
            &request,
            &identity,
            schema,
        )
        .expect("named principal maps")
        .principal()
        .expect("principal is present")
        .to_string();

        assert_eq!(default_uid, r#"Box::Agent::"self""#);
        assert_eq!(named_uid, r#"Box::Agent::"self""#);
        assert_eq!(default_uid, named_uid);
    }

    /// Every id [`action_id`] can return must have a cached UID. A verb added to the
    /// `action` module but not to `ACTION_IDS` would otherwise fail closed at runtime
    /// (`unknown action id`) instead of at compile or test time — a whole action silently
    /// undecidable.
    #[test]
    fn every_action_id_has_a_cached_uid() {
        for id in ACTION_IDS {
            assert!(
                fixed_action_uid(id).is_ok(),
                "no cached action uid for {id}; add it to ACTION_IDS"
            );
        }
        assert!(
            fixed_action_uid("fs:raed").is_err(),
            "an unknown action id must not resolve to a uid"
        );
    }

    /// Every kernel verb collapses to its customer-altitude action, and
    /// that action is a real cached id. The explicit expectations pin the collapse: the
    /// fine verb rides `operation`, but the coarse action a rule names is one of
    /// read/write/delete/move/other. `ExecFile` folds into `fs:read`, because the
    /// executability probe is a metadata disclosure and running a program is a shell
    /// decision. A verb added to [`FsOperation`] and mapped to an id missing from
    /// `ACTION_IDS` would resolve to no cached UID and fail closed at runtime — this
    /// catches it here instead.
    #[test]
    fn every_fs_action_maps_to_a_coarse_verb_in_the_cached_id_list() {
        // Every variant, so adding one to `FsOperation` without mapping it here fails.
        // `FsOperation` is `#[non_exhaustive]` to callers but exhaustively matchable
        // inside the crate, and `fs_action_id` matches it exhaustively.
        let cases = [
            (FsOperation::ReadContent, action::FS_READ),
            (FsOperation::ReadMetadata, action::FS_READ),
            (FsOperation::Enumerate, action::FS_READ),
            (FsOperation::ReadLink, action::FS_READ),
            (FsOperation::ChangeDir, action::FS_READ),
            (FsOperation::ExecFile, action::FS_READ),
            (FsOperation::WriteContent, action::FS_WRITE),
            (FsOperation::CreateDir, action::FS_WRITE),
            (FsOperation::SetPermissions, action::FS_WRITE),
            (FsOperation::Symlink, action::FS_WRITE),
            (FsOperation::RemoveFile, action::FS_DELETE),
            (FsOperation::RemoveDir, action::FS_DELETE),
            (FsOperation::Rename, action::FS_MOVE),
            (FsOperation::Other, action::FS_OTHER),
        ];
        for (operation, expected) in cases {
            let id = fs_action_id(operation);
            assert_eq!(
                id, expected,
                "{operation:?} maps to the wrong coarse action"
            );
            assert!(
                ACTION_IDS.contains(&id),
                "{operation:?} authorizes `{id}`, which is missing from ACTION_IDS"
            );
        }
    }
}

/// The box associated with an integration boundary.
///
/// The policy identity stays `Box::Resource::"unused"`. This value retains integration metadata
/// for the stable facade and does not enter policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedBox {
    name: String,
}

impl GovernedBox {
    /// Name the box an endpoint belongs to.
    ///
    /// The caller must pass a name it derived from the endpoint it owns, never a name read
    /// from a request.
    #[must_use]
    pub fn assigned(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Return the assigned box name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}
