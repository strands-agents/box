//! Audit records.

/// A request correlation id, tying every record about one exchange together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestId {
    value: String,
    context: std::collections::BTreeMap<String, String>,
}

impl RequestId {
    /// Create a request id from its string representation.
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            context: Default::default(),
        }
    }

    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Read one allowlisted trace or harness correlation field.
    pub fn context(&self, name: &str) -> Option<&str> {
        self.context.get(name).map(String::as_str)
    }

    #[cfg(feature = "tls-intercept")]
    pub(crate) fn unique() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self::new(format!("egress-{}-{at}-{sequence}", std::process::id()))
    }

    #[cfg(any(test, feature = "tls-intercept"))]
    pub(crate) fn with_headers(mut self, headers: &crate::boundary::HeaderMap) -> Self {
        for key in ["traceparent", "tracestate", "conversation_id"] {
            self.context.remove(key);
        }
        let mut parents = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("traceparent"))
            .map(|(_, value)| value);
        if let (Some(parent), None) = (parents.next(), parents.next()) {
            self.set_context("traceparent", Some(parent));
            let state = headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("tracestate"))
                .map(|(_, value)| value)
                .try_fold(String::new(), |mut combined, value| {
                    let separator = usize::from(!combined.is_empty());
                    if combined.len() + separator + value.len() > 512 {
                        return None;
                    }
                    if separator != 0 {
                        combined.push(',');
                    }
                    combined.push_str(value);
                    Some(combined)
                });
            self.set_context(
                "tracestate",
                state.as_deref().filter(|state| !state.is_empty()),
            );
        }
        self.set_context(
            "conversation_id",
            headers
                .get("thread-id")
                .or_else(|| headers.get("session-id")),
        );
        self
    }

    #[cfg(feature = "tls-intercept")]
    pub(crate) fn with_mcp(mut self, body: &[u8]) -> Self {
        #[derive(serde::Deserialize)]
        struct Message {
            id: Option<serde_json::Value>,
            method: Option<String>,
            params: Option<Params>,
        }
        #[derive(serde::Deserialize)]
        struct Params {
            #[serde(rename = "_meta")]
            meta: Option<Meta>,
            name: Option<String>,
        }
        #[derive(serde::Deserialize)]
        struct Meta {
            traceparent: Option<String>,
            tracestate: Option<String>,
            #[serde(rename = "threadId")]
            thread: Option<String>,
            #[serde(rename = "sessionId")]
            conversation: Option<String>,
            #[serde(rename = "callId")]
            call: Option<String>,
        }
        let Ok(message) = serde_json::from_slice::<Message>(body) else {
            return self;
        };
        self.set_context("mcp_method", message.method.as_deref());
        let id = message.id.and_then(|id| match id {
            serde_json::Value::String(id) => Some(id),
            serde_json::Value::Number(id) => Some(id.to_string()),
            _ => None,
        });
        self.set_context("jsonrpc_request_id", id.as_deref());
        if let Some(params) = message.params {
            if message.method.as_deref() == Some("tools/call") {
                self.set_context("tool_name", params.name.as_deref());
            }
            let Some(meta) = params.meta else { return self };
            for (key, value) in [
                ("mcp_traceparent", meta.traceparent.as_deref()),
                ("mcp_tracestate", meta.tracestate.as_deref()),
                (
                    "conversation_id",
                    meta.thread.as_deref().or(meta.conversation.as_deref()),
                ),
                ("tool_call_id", meta.call.as_deref()),
            ] {
                self.set_context(key, value);
            }
        }
        self
    }

    #[cfg(any(test, feature = "tls-intercept"))]
    fn set_context(&mut self, key: &str, value: Option<&str>) {
        if let Some(value) = value.filter(|value| value.len() <= 512 && value.is_ascii()) {
            self.context.insert(key.to_string(), value.to_string());
        }
    }
}

/// Whether the boundary allowed or denied a request/response — the outcome an audit record carries
/// (secret-free).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request/response was allowed (possibly with mutations applied).
    Allow,
    /// The request/response was denied and blocked.
    Deny,
}

/// One final connection or outbound request decision emitted before its result is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressDecision {
    /// The destination host.
    pub host: String,
    /// The destination port.
    pub port: u16,
    /// The request method, or empty for a connection decision.
    pub method: String,
    /// The request path, or `/` for a connection decision.
    pub path: String,
    /// The allow/deny outcome.
    pub decision: Decision,
    /// A non-secret reason (the deny reason), or empty for an allow.
    pub reason: String,
    /// The correlation id tying this to the matching `CredentialAcquire`.
    pub correlation: RequestId,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corr() -> RequestId {
        RequestId::new("turn-1")
    }

    #[test]
    fn split_tracestate_fields_keep_order_and_duplicate_keys_for_validation() {
        let mut headers = crate::boundary::HeaderMap::new();
        headers.append(
            "traceparent",
            "00-11111111111111111111111111111111-2222222222222222-01",
        );
        headers.append("tracestate", "a=1");
        headers.append("TraceState", "b=2");
        let request = corr().with_headers(&headers);
        assert_eq!(request.context("tracestate"), Some("a=1,b=2"));

        headers.append("tracestate", "a=3");
        let request = corr().with_headers(&headers);
        assert_eq!(request.context("tracestate"), Some("a=1,b=2,a=3"));
    }

    #[test]
    fn ambiguous_or_missing_headers_never_reuse_an_earlier_parent() {
        let mut headers = crate::boundary::HeaderMap::new();
        headers.append(
            "traceparent",
            "00-11111111111111111111111111111111-2222222222222222-01",
        );
        headers.append("tracestate", "a=1");
        let request = corr().with_headers(&headers);
        assert!(request.context("traceparent").is_some());

        let empty = request
            .clone()
            .with_headers(&crate::boundary::HeaderMap::new());
        assert_eq!(empty.context("traceparent"), None);
        assert_eq!(empty.context("tracestate"), None);

        headers.append(
            "TraceParent",
            "00-33333333333333333333333333333333-4444444444444444-01",
        );
        let ambiguous = request.with_headers(&headers);
        assert_eq!(ambiguous.context("traceparent"), None);
        assert_eq!(ambiguous.context("tracestate"), None);
    }

    #[test]
    fn combined_tracestate_has_one_shared_size_bound() {
        let mut headers = crate::boundary::HeaderMap::new();
        headers.append(
            "traceparent",
            "00-11111111111111111111111111111111-2222222222222222-01",
        );
        headers.append("tracestate", format!("a={}", "1".repeat(255)));
        headers.append("tracestate", format!("b={}", "2".repeat(255)));
        let request = corr().with_headers(&headers);
        assert!(request.context("traceparent").is_some());
        assert_eq!(request.context("tracestate"), None);
    }
}
