//! What an MCP request frame asks a server to do, for both kinds of MCP server.
//!
//! | Item | Role |
//! |---|---|
//! | [`McpTarget`] | the decided method and the item it names, or `None` for a frame that asks nothing |
//! | [`mcp_denial_response`] | the JSON-RPC error a refused request receives |
//! | [`canonicalize_mcp_frame`] | the `resources/read` frame the server receives, with its canonical URI |

mod uri;

use std::io;

use serde_json::Value;

#[cfg(feature = "tls-intercept")]
pub(crate) use uri::{decode_unreserved, remove_dot_segments};

/// The methods a stdio server receives undecided, because its connection cannot start without them.
const STDIO_UNDECIDED_METHODS: [&str; 4] = [
    "initialize",
    "server/discover",
    "ping",
    "subscriptions/listen",
];

/// The methods an HTTP server receives undecided; `initialize` is decided, so a rule can gate it.
const HTTP_UNDECIDED_METHODS: [&str; 3] = ["server/discover", "ping", "subscriptions/listen"];

/// A decided MCP request: the item it names, and its arguments.
#[derive(Clone, Debug, PartialEq)]
pub struct McpTarget {
    /// The item the request names.
    pub identity: McpTargetIdentity,
    /// The request's `params.arguments` as JSON text, `{}` when it carries no object.
    pub arguments: String,
}

/// The item a decided MCP method names.
#[derive(Clone, Debug, PartialEq)]
pub enum McpTargetIdentity {
    /// `tools/call`: the tool name.
    Tool(String),
    /// `prompts/get`: the prompt name.
    Prompt(String),
    /// `resources/read`: the canonical resource URI.
    Resource(String),
    /// Any other decided method: the method itself.
    Method(String),
}

impl McpTarget {
    /// Classify one request frame to a stdio server, or refuse a frame the box cannot judge.
    pub fn of_stdio_request(frame: &[u8]) -> io::Result<Option<Self>> {
        Self::of(frame, &STDIO_UNDECIDED_METHODS)
    }

    /// Classify one request frame to an HTTP server, or refuse a frame the box cannot judge.
    pub fn of_http_request(frame: &[u8]) -> io::Result<Option<Self>> {
        Self::of(frame, &HTTP_UNDECIDED_METHODS)
    }

    fn of(frame: &[u8], undecided: &[&str]) -> io::Result<Option<Self>> {
        if frame.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        let refuse = |reason: String| io::Error::new(io::ErrorKind::InvalidData, reason);

        let parsed: Value = serde_json::from_slice(frame).map_err(|error| {
            refuse(format!(
                "an MCP frame the box cannot parse is refused rather than forwarded: {error}"
            ))
        })?;
        // A batch carries every method past a `get("method")` check, so it is refused unopened.
        let Some(object) = parsed.as_object() else {
            return Err(refuse(
                "an MCP frame that is not a JSON object is refused: a batch or a bare value carries \
                 no method the box can decide"
                    .to_string(),
            ));
        };
        let method = match object.get("method") {
            Some(Value::String(method)) => method.as_str(),
            None if object.contains_key("result") || object.contains_key("error") => {
                return Err(refuse(
                    "a client-sent JSON-RPC response is refused: it answers no request the server \
                     sent, and the box will not forward an unjudged frame"
                        .to_string(),
                ));
            }
            _ => {
                return Err(refuse(
                    "an MCP frame that is neither a request naming a string method nor a response \
                     is refused: the box cannot say what it would forward"
                        .to_string(),
                ));
            }
        };
        // `{"id":7,"method":"notifications/x"}` opens a reply channel, so it is not a notification.
        let is_notification = method.starts_with("notifications/") && !object.contains_key("id");
        if undecided.contains(&method) || is_notification {
            return Ok(None);
        }

        let named = |key: &str| -> io::Result<String> {
            match object
                .get("params")
                .and_then(|params| params.get(key))
                .and_then(Value::as_str)
            {
                Some(item) if !item.is_empty() => Ok(item.to_string()),
                _ => Err(refuse(
                    "an act frame naming no item is refused: the box cannot decide what it cannot \
                     name"
                        .to_string(),
                )),
            }
        };
        let identity = match method {
            "tools/call" => McpTargetIdentity::Tool(named("name")?),
            "prompts/get" => McpTargetIdentity::Prompt(named("name")?),
            "resources/read" => {
                McpTargetIdentity::Resource(uri::canonicalize_resource_uri(&named("uri")?))
            }
            other => McpTargetIdentity::Method(other.to_string()),
        };
        Ok(Some(Self {
            identity,
            arguments: raw_arguments(object),
        }))
    }

    /// The JSON-RPC method.
    pub fn method(&self) -> &str {
        match &self.identity {
            McpTargetIdentity::Tool(_) => "tools/call",
            McpTargetIdentity::Prompt(_) => "prompts/get",
            McpTargetIdentity::Resource(_) => "resources/read",
            McpTargetIdentity::Method(method) => method,
        }
    }

    /// The tool a `tools/call` names.
    pub fn tool(&self) -> Option<&str> {
        match &self.identity {
            McpTargetIdentity::Tool(tool) => Some(tool),
            _ => None,
        }
    }

    /// The prompt a `prompts/get` names.
    pub fn prompt(&self) -> Option<&str> {
        match &self.identity {
            McpTargetIdentity::Prompt(prompt) => Some(prompt),
            _ => None,
        }
    }

    /// The canonical resource URI a `resources/read` names.
    pub fn uri(&self) -> Option<&str> {
        match &self.identity {
            McpTargetIdentity::Resource(uri) => Some(uri),
            _ => None,
        }
    }

    /// The item a record and a denial name: the per-item identity, or the method.
    pub fn reported(&self) -> &str {
        match &self.identity {
            McpTargetIdentity::Tool(item)
            | McpTargetIdentity::Prompt(item)
            | McpTargetIdentity::Resource(item)
            | McpTargetIdentity::Method(item) => item,
        }
    }
}

/// The JSON-RPC error for a refused request, or `None` when the frame has no id to answer.
pub fn mcp_denial_response(frame: &[u8], message: &str) -> Option<String> {
    let request: Value = serde_json::from_slice(frame).ok()?;
    let object = request.as_object()?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return None;
    }
    let id = object
        .get("id")
        .filter(|id| id.is_string() || id.is_number())?;
    Some(
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32001, "message": message}
        })
        .to_string(),
    )
}

/// The frame with its `resources/read` URI canonicalized, or `None` when nothing changes.
pub fn canonicalize_mcp_frame(frame: &[u8]) -> Option<Vec<u8>> {
    uri::canonicalize_frame_uri(frame)
}

fn raw_arguments(object: &serde_json::Map<String, Value>) -> String {
    object
        .get("params")
        .and_then(|params| params.get("arguments"))
        .filter(|value| value.is_object())
        .map_or_else(|| "{}".to_string(), Value::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(body: &[u8]) -> Option<McpTargetIdentity> {
        McpTarget::of_http_request(body)
            .unwrap()
            .map(|target| target.identity)
    }

    #[test]
    fn tools_call_reports_the_tool_name() {
        let frame = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add"}}"#;
        assert_eq!(identity(frame), Some(McpTargetIdentity::Tool("add".into())));
    }

    #[test]
    fn tools_call_captures_raw_arguments_including_non_scalars() {
        let frame = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create","arguments":{"private":false,"labels":["a","b"],"repo":{"owner":"x"}}}}"#;
        let target = McpTarget::of_http_request(frame).unwrap().unwrap();
        assert_eq!(target.identity, McpTargetIdentity::Tool("create".into()));
        let arguments: Value = serde_json::from_str(&target.arguments).unwrap();
        assert_eq!(arguments["private"], serde_json::json!(false));
        assert_eq!(arguments["labels"], serde_json::json!(["a", "b"]));
        assert_eq!(arguments["repo"], serde_json::json!({"owner": "x"}));
    }

    #[test]
    fn a_frame_with_no_arguments_captures_an_empty_object() {
        let frame = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add"}}"#;
        let target = McpTarget::of_http_request(frame).unwrap().unwrap();
        assert_eq!(target.arguments, "{}");
    }

    #[test]
    fn resources_read_reports_the_uri() {
        let frame =
            br#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///x"}}"#;
        assert_eq!(
            identity(frame),
            Some(McpTargetIdentity::Resource("file:///x".into()))
        );
    }

    #[test]
    fn a_respelled_resources_read_uri_canonicalizes_to_one_identity() {
        for raw in [
            "file:/etc/passwd",
            "file:///%65tc/passwd",
            "file:///tmp/../etc/passwd",
        ] {
            let frame = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{{"uri":"{raw}"}}}}"#
            );
            for classify in [McpTarget::of_stdio_request, McpTarget::of_http_request] {
                assert_eq!(
                    classify(frame.as_bytes())
                        .unwrap()
                        .map(|target| target.identity),
                    Some(McpTargetIdentity::Resource("file:///etc/passwd".into())),
                    "{raw} must canonicalize to the one identity the server resolves"
                );
            }
        }
    }

    #[test]
    fn canonicalize_mcp_frame_rewrites_the_forwarded_resources_read_uri() {
        let raw = br#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///tmp/../etc/passwd"}}"#;
        let rewritten = canonicalize_mcp_frame(raw).expect("a respelled uri is rewritten");
        let value: Value = serde_json::from_slice(&rewritten).expect("valid JSON");
        assert_eq!(value["params"]["uri"], "file:///etc/passwd");
        assert!(
            canonicalize_mcp_frame(br#"{"jsonrpc":"2.0","id":1,"method":"resources/subscribe","params":{"uri":"file:///%65tc"}}"#)
                .is_none(),
            "only resources/read is rewritten"
        );
        assert!(
            canonicalize_mcp_frame(br#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}"#)
                .is_none(),
            "an already-canonical uri produces no rewrite"
        );
    }

    #[test]
    fn list_and_unknown_methods_report_the_method() {
        assert_eq!(
            identity(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
            Some(McpTargetIdentity::Method("tools/list".into()))
        );
        assert_eq!(
            identity(br#"{"jsonrpc":"2.0","id":1,"method":"future/method"}"#),
            Some(McpTargetIdentity::Method("future/method".into()))
        );
    }

    #[test]
    fn the_protocol_floor_is_not_gated() {
        for classify in [McpTarget::of_stdio_request, McpTarget::of_http_request] {
            for method in ["server/discover", "ping", "subscriptions/listen"] {
                let frame = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#);
                assert_eq!(classify(frame.as_bytes()).unwrap(), None, "{method}");
            }
            let note = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
            assert_eq!(classify(note).unwrap(), None);
        }
    }

    #[test]
    fn initialize_is_decided_on_http_and_undecided_on_stdio() {
        let frame = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        assert_eq!(
            identity(frame),
            Some(McpTargetIdentity::Method("initialize".into()))
        );
        assert_eq!(McpTarget::of_stdio_request(frame).unwrap(), None);
    }

    #[test]
    fn malformed_frames_are_refused() {
        for classify in [McpTarget::of_stdio_request, McpTarget::of_http_request] {
            assert!(classify(b"not json").is_err());
            assert!(classify(b"[{\"method\":\"tools/call\"}]").is_err());
            assert!(classify(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#).is_err());
            assert_eq!(
                classify(br#"{"jsonrpc":"2.0","id":7,"method":"notifications/x"}"#)
                    .unwrap()
                    .map(|target| target.identity),
                Some(McpTargetIdentity::Method("notifications/x".into()))
            );
            assert!(classify(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#).is_err());
            assert!(classify(br#"{"jsonrpc":"2.0","id":1,"method":"resources/read"}"#).is_err());
        }
    }

    #[test]
    fn a_denial_answers_only_an_id_bearing_json_rpc_request() {
        let response = mcp_denial_response(
            br#"{"jsonrpc":"2.0","id":4,"method":"tools/call"}"#,
            "denied",
        )
        .expect("an id-bearing request is answered");
        let value: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(value["id"], 4);
        assert_eq!(value["error"]["code"], -32001);
        assert!(
            mcp_denial_response(br#"{"jsonrpc":"2.0","method":"tools/call"}"#, "denied").is_none()
        );
        assert!(mcp_denial_response(br#"{"id":4,"method":"tools/call"}"#, "denied").is_none());
    }
}
