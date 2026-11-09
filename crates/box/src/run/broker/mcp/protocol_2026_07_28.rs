//! Per-request protocol metadata and the inputs a modern MCP request can carry.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::jsonrpc::invalid_data;

pub(super) const PROTOCOL_VERSION: &str = "2026-07-28";
pub(super) const MAXIMUM_PENDING: usize = 64;
pub(super) const MAXIMUM_CANCELLED: usize = 1024;
pub(super) const MAXIMUM_CANCELLED_BYTES: usize = 16 * 1024 * 1024;
const VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
const INFO_KEY: &str = "io.modelcontextprotocol/clientInfo";

pub(super) type InputKey = [u8; 32];

pub(super) struct ProtocolError {
    code: i32,
    pub(super) message: String,
    data: Option<Value>,
}

impl ProtocolError {
    fn params(message: &str) -> Self {
        Self {
            code: -32602,
            message: message.to_string(),
            data: None,
        }
    }

    pub(super) fn response(&self, id: &Value) -> Value {
        let mut error = json!({"code": self.code, "message": self.message});
        if let Some(data) = &self.data {
            error["data"] = data.clone();
        }
        json!({"jsonrpc": "2.0", "id": id, "error": error})
    }
}

pub(super) struct ModernRequest {
    pub(super) method: String,
    binding: InputKey,
    capabilities: BTreeSet<&'static str>,
}

pub(super) struct PendingInputs {
    pub(super) key: InputKey,
    pub(super) methods: BTreeMap<String, String>,
}

pub(super) enum ModernReply {
    Complete,
    InputRequired(PendingInputs),
    LegacyProbe,
}

pub(super) fn carries_metadata(request: &Value) -> bool {
    request["params"]["_meta"].as_object().is_some_and(|meta| {
        [VERSION_KEY, CAPABILITIES_KEY, INFO_KEY]
            .iter()
            .any(|key| meta.contains_key(*key))
    })
}

pub(super) fn carries_inputs(request: &Value) -> bool {
    request["params"].as_object().is_some_and(|params| {
        params.contains_key("inputResponses") || params.contains_key("requestState")
    })
}

impl ModernRequest {
    pub(super) fn parse(request: &Value) -> Result<Self, ProtocolError> {
        if request.get("result").is_some() || request.get("error").is_some() {
            return Err(ProtocolError::params(
                "an MCP request cannot also be a response",
            ));
        }
        if !request
            .get("id")
            .is_some_and(|id| id.is_string() || id.is_i64() || id.is_u64())
        {
            return Err(ProtocolError::params(
                "a modern MCP request needs a string or integer id",
            ));
        }
        let params = request
            .get("params")
            .and_then(Value::as_object)
            .ok_or_else(|| ProtocolError::params("modern MCP params must be an object"))?;
        let meta = params
            .get("_meta")
            .and_then(Value::as_object)
            .ok_or_else(|| ProtocolError::params("modern MCP requests require params._meta"))?;
        let version = meta
            .get(VERSION_KEY)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProtocolError::params("modern MCP requests require a protocolVersion string")
            })?;
        let capabilities = meta
            .get(CAPABILITIES_KEY)
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ProtocolError::params("modern MCP requests require a clientCapabilities object")
            })?;
        if let Some(info) = meta.get(INFO_KEY)
            && (!info.is_object() || !info["name"].is_string() || !info["version"].is_string())
        {
            return Err(ProtocolError::params(
                "MCP clientInfo must contain string name and version fields",
            ));
        }
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError {
                code: -32022,
                message: "Unsupported MCP protocol version".to_string(),
                data: Some(json!({"requested": version, "supported": [PROTOCOL_VERSION]})),
            });
        }
        if params
            .get("requestState")
            .is_some_and(|state| !state.is_string())
            || params
                .get("inputResponses")
                .is_some_and(|inputs| !inputs.is_object())
        {
            return Err(ProtocolError::params(
                "MCP requestState must be a string and inputResponses must be an object",
            ));
        }
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| ProtocolError::params("an MCP request must name a method"))?;
        if carries_inputs(request) && !supports_inputs(method) {
            return Err(ProtocolError::params(
                "this MCP method cannot carry inputResponses or requestState",
            ));
        }
        let mut declared = BTreeSet::new();
        for capability in ["roots", "sampling", "elicitation"] {
            if let Some(value) = capabilities.get(capability) {
                if !value.is_object() {
                    return Err(ProtocolError::params(
                        "MCP client capabilities must be objects",
                    ));
                }
                declared.insert(capability);
            }
        }
        let mut ordinary = params.clone();
        for field in ["_meta", "inputResponses", "requestState"] {
            ordinary.remove(field);
        }
        let mut identity = json!({"method": method, "params": ordinary});
        identity.sort_all_objects();
        let binding = Sha256::digest(identity.to_string().as_bytes()).into();
        Ok(Self {
            method: method.to_string(),
            binding,
            capabilities: declared,
        })
    }

    pub(super) fn retry_key(&self, request: &Value) -> Option<InputKey> {
        carries_inputs(request).then(|| self.input_key(request["params"].get("requestState")))
    }

    fn input_key(&self, state: Option<&Value>) -> InputKey {
        let mut hash = Sha256::new();
        hash.update(self.binding);
        hash.update(state.unwrap_or(&Value::Null).to_string().as_bytes());
        hash.finalize().into()
    }

    pub(super) fn validate_reply(&self, response: &Value) -> io::Result<ModernReply> {
        if response.get("error").is_some() && response.get("result").is_some() {
            return Err(invalid_data(
                "an MCP response cannot contain both result and error",
            ));
        }
        if let Some(error) = response.get("error") {
            let code = error["code"]
                .as_i64()
                .ok_or_else(|| invalid_data("an MCP error needs an integer code"))?;
            if !error["message"].is_string() {
                return Err(invalid_data("an MCP error needs a message"));
            }
            return Ok(
                if self.method == "server/discover" && !matches!(code, -32022..=-32020) {
                    ModernReply::LegacyProbe
                } else {
                    ModernReply::Complete
                },
            );
        }
        let result = response
            .get("result")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_data("a modern MCP response needs a result object"))?;
        match result.get("resultType").and_then(Value::as_str) {
            Some("complete") => {}
            Some("input_required") => return self.pending_inputs(response),
            _ => {
                return Err(invalid_data(
                    "a modern MCP result has an unsupported resultType",
                ));
            }
        }
        if matches!(
            self.method.as_str(),
            "server/discover"
                | "tools/list"
                | "prompts/list"
                | "resources/list"
                | "resources/read"
                | "resources/templates/list"
        ) && (result.get("ttlMs").and_then(Value::as_u64).is_none()
            || !matches!(
                result.get("cacheScope").and_then(Value::as_str),
                Some("public" | "private")
            ))
        {
            return Err(invalid_data(
                "a modern MCP cacheable result needs ttlMs and cacheScope",
            ));
        }
        if self.method == "server/discover"
            && (!result.get("capabilities").is_some_and(Value::is_object)
                || !result
                    .get("supportedVersions")
                    .and_then(Value::as_array)
                    .is_some_and(|versions| {
                        !versions.is_empty() && versions.iter().all(Value::is_string)
                    }))
        {
            return Err(invalid_data(
                "MCP server/discover needs supportedVersions and capabilities",
            ));
        }
        Ok(ModernReply::Complete)
    }

    fn pending_inputs(&self, response: &Value) -> io::Result<ModernReply> {
        if !supports_inputs(&self.method) {
            return Err(invalid_data("this MCP method cannot return input_required"));
        }
        let result = &response["result"];
        let state = result.get("requestState");
        if state.is_some_and(|state| !state.is_string()) {
            return Err(invalid_data("MCP requestState must be a string"));
        }
        let requests = result
            .get("inputRequests")
            .map(|requests| {
                requests
                    .as_object()
                    .ok_or_else(|| invalid_data("MCP inputRequests must be an object"))
            })
            .transpose()?;
        if requests.is_none() && state.is_none() {
            return Err(invalid_data(
                "MCP input_required needs inputRequests or requestState",
            ));
        }
        let mut methods = BTreeMap::new();
        if let Some(requests) = requests {
            if requests.len() > MAXIMUM_PENDING {
                return Err(invalid_data("too many MCP input requests"));
            }
            for (key, request) in requests {
                let method = request["method"].as_str().unwrap_or_default();
                let capability = match method {
                    "roots/list" => "roots",
                    "sampling/createMessage" => "sampling",
                    "elicitation/create" => "elicitation",
                    _ => return Err(invalid_data("unsupported MCP input request method")),
                };
                if key.len() > 256 || !self.capabilities.contains(capability) {
                    return Err(invalid_data(
                        "MCP input request exceeds its id limit or client capabilities",
                    ));
                }
                methods.insert(key.clone(), method.to_string());
            }
        }
        Ok(ModernReply::InputRequired(PendingInputs {
            key: self.input_key(state),
            methods,
        }))
    }
}

fn supports_inputs(method: &str) -> bool {
    matches!(method, "tools/call" | "prompts/get" | "resources/read")
}

pub(super) fn request_meta() -> Value {
    json!({
        VERSION_KEY: PROTOCOL_VERSION,
        CAPABILITIES_KEY: {},
        INFO_KEY: {"name": "strands-box", "version": env!("CARGO_PKG_VERSION")}
    })
}
