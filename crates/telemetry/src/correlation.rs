//! Request-scoped trace context and bounded correlation identifiers.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;

use opentelemetry::propagation::TextMapPropagator as _;
use opentelemetry::trace::{SpanContext, TraceContextExt as _};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use serde::{Deserialize, Serialize};

/// Correlation hints supplied by one request, never authorization inputs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "UnvalidatedCorrelation")]
pub struct Correlation {
    #[serde(skip_serializing_if = "Option::is_none")]
    traceparent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tracestate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jsonrpc_request_id: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct UnvalidatedCorrelation {
    traceparent: Option<String>,
    tracestate: Option<String>,
    request_id: Option<String>,
    jsonrpc_request_id: Option<String>,
}

impl From<UnvalidatedCorrelation> for Correlation {
    fn from(value: UnvalidatedCorrelation) -> Self {
        Self::from_headers(value.traceparent.as_deref(), value.tracestate.as_deref())
            .request(value.request_id.as_deref())
            .mcp(value.jsonrpc_request_id.as_deref())
    }
}

thread_local! {
    static CURRENT: RefCell<Correlation> = RefCell::new(Correlation::default());
}

impl Correlation {
    /// Parse W3C headers, ignoring invalid or oversized context.
    #[must_use]
    pub fn from_headers(traceparent: Option<&str>, tracestate: Option<&str>) -> Self {
        let mut headers = HashMap::new();
        if let Some(parent) = traceparent.filter(|parent| valid_parent_shape(parent)) {
            headers.insert("traceparent".to_string(), parent.to_string());
        }
        if let Some(state) = tracestate.and_then(normalized_state) {
            headers.insert("tracestate".to_string(), state);
        }
        let context = TraceContextPropagator::new()
            .extract_with_context(&opentelemetry::Context::new(), &headers);
        let span = context.span();
        let parent = span.span_context();
        if !parent.is_valid() {
            return Self::default();
        }
        Self {
            traceparent: Some(format!(
                "00-{}-{}-{:02x}",
                parent.trace_id(),
                parent.span_id(),
                traceparent
                    .and_then(|value| value.split('-').nth(3))
                    .and_then(|value| u8::from_str_radix(value, 16).ok())
                    .unwrap_or(0)
                    & 3
            )),
            tracestate: (!parent.trace_state().header().is_empty())
                .then(|| parent.trace_state().header()),
            ..Self::default()
        }
    }

    /// Supply the request's W3C headers unless the caller supplied its own parent.
    pub fn inject_http(&self, headers: &mut Vec<(String, String)>) {
        if headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("traceparent"))
        {
            return;
        }
        if let Some(parent) = &self.traceparent {
            headers.retain(|(name, _)| !name.eq_ignore_ascii_case("tracestate"));
            headers.push(("traceparent".to_string(), parent.clone()));
            if let Some(state) = &self.tracestate {
                headers.push(("tracestate".to_string(), state.clone()));
            }
        }
    }

    /// Attach the transport request identifier.
    #[must_use]
    pub fn request(mut self, value: Option<&str>) -> Self {
        self.request_id = identifier(value);
        self
    }

    /// Attach the JSON-RPC identifier of one MCP message.
    #[must_use]
    pub fn mcp(mut self, request_id: Option<&str>) -> Self {
        self.jsonrpc_request_id = identifier(request_id);
        self
    }

    /// Prefer message context, and take the transport's parent when the message carries none.
    #[must_use]
    pub fn with_transport(mut self, transport: Self) -> Self {
        if !self.parent().is_valid() {
            self.traceparent = transport.traceparent;
            self.tracestate = transport.tracestate;
        }
        self.request_id = self.request_id.or(transport.request_id);
        self
    }

    /// Read only named correlation fields from one MCP JSON-RPC request.
    #[must_use]
    pub fn from_mcp(frame: &str) -> Self {
        #[derive(Deserialize)]
        struct Message {
            id: Option<serde_json::Value>,
            params: Option<Params>,
        }
        #[derive(Deserialize)]
        struct Params {
            #[serde(rename = "_meta")]
            meta: Option<Meta>,
        }
        #[derive(Deserialize, Default)]
        struct Meta {
            traceparent: Option<String>,
            tracestate: Option<String>,
        }
        let Ok(message) = serde_json::from_str::<Message>(frame) else {
            return Self::default();
        };
        let meta = message
            .params
            .and_then(|params| params.meta)
            .unwrap_or_default();
        let id = message.id.and_then(|id| match id {
            serde_json::Value::String(id) => Some(id),
            serde_json::Value::Number(id) => Some(id.to_string()),
            _ => None,
        });
        Self::from_headers(meta.traceparent.as_deref(), meta.tracestate.as_deref())
            .mcp(id.as_deref())
    }

    /// Read the context of the operation currently being polled.
    #[must_use]
    pub fn current() -> Self {
        CURRENT.with(|current| current.borrow().clone())
    }

    /// Apply this context only while the operation runs synchronously.
    pub fn during<T>(&self, operation: impl FnOnce() -> T) -> T {
        struct Restore(Correlation);
        impl Drop for Restore {
            fn drop(&mut self) {
                CURRENT.with(|current| *current.borrow_mut() = std::mem::take(&mut self.0));
            }
        }
        let _restore = Restore(
            CURRENT.with(|current| std::mem::replace(&mut *current.borrow_mut(), self.clone())),
        );
        operation()
    }

    /// Restore the caller's context after every poll, including pending and panic.
    pub async fn scope<T>(&self, operation: impl Future<Output = T>) -> T {
        let mut operation = std::pin::pin!(operation);
        std::future::poll_fn(|cx| self.during(|| operation.as_mut().poll(cx))).await
    }

    pub(crate) fn parent(&self) -> SpanContext {
        let validated = Self::from_headers(self.traceparent.as_deref(), self.tracestate.as_deref());
        let mut headers = HashMap::new();
        if let Some(value) = validated.traceparent {
            headers.insert("traceparent".to_string(), value);
        }
        if let Some(value) = validated.tracestate {
            headers.insert("tracestate".to_string(), value);
        }
        let parent = TraceContextPropagator::new()
            .extract_with_context(&opentelemetry::Context::new(), &headers)
            .span()
            .span_context()
            .clone();
        let flags = headers
            .get("traceparent")
            .and_then(|value| value.split('-').nth(3))
            .and_then(|value| u8::from_str_radix(value, 16).ok())
            .unwrap_or(0)
            & 3;
        SpanContext::new(
            parent.trace_id(),
            parent.span_id(),
            opentelemetry::trace::TraceFlags::new(flags),
            parent.is_remote(),
            parent.trace_state().clone(),
        )
    }

    pub(crate) fn attributes(&self) -> Vec<(&'static str, String)> {
        [
            ("strands.box.request.id", self.request_id.as_deref()),
            ("jsonrpc.request.id", self.jsonrpc_request_id.as_deref()),
        ]
        .into_iter()
        .filter_map(|(key, value)| identifier(value).map(|value| (key, value)))
        .collect()
    }
}

fn identifier(value: Option<&str>) -> Option<String> {
    value
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 256
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
                })
        })
        .map(str::to_string)
}

fn normalized_state(value: &str) -> Option<String> {
    if value.len() > 512 {
        return None;
    }
    let mut keys = std::collections::HashSet::new();
    let mut members = Vec::new();
    for member in value.split(',') {
        let member = member.trim_matches([' ', '\t']);
        if member.is_empty() {
            continue;
        }
        let (key, state) = member.split_once('=')?;
        if key.is_empty()
            || keys.len() == 32
            || !keys.insert(key)
            || state.is_empty()
            || !state
                .bytes()
                .all(|byte| (0x20..=0x7e).contains(&byte) && byte != b'=')
        {
            return None;
        }
        members.push(member);
    }
    Some(members.join(","))
}

fn valid_parent_shape(value: &str) -> bool {
    if !(55..=512).contains(&value.len()) {
        return false;
    }
    let parts: Vec<_> = value.split('-').collect();
    parts.len() >= 4
        && (parts[0] != "00" || parts.len() == 4)
        && parts[0].len() == 2
        && parts[1].len() == 32
        && parts[2].len() == 16
        && parts[3].len() == 2
        && parts[..4].iter().all(|part| {
            part.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";

    #[test]
    fn deserialization_discards_unbounded_and_invalid_context() {
        let raw = serde_json::json!({
            "traceparent": PARENT,
            "tracestate": "x".repeat(1024),
            "request_id": "private text\nsecret",
            "jsonrpc_request_id": "7"
        });
        let correlation: Correlation = serde_json::from_value(raw).unwrap();
        assert!(correlation.parent().is_valid());
        assert_eq!(
            correlation.attributes(),
            vec![("jsonrpc.request.id", "7".into())]
        );
        assert_eq!(
            serde_json::to_value(correlation).unwrap(),
            serde_json::json!({
                "traceparent": PARENT,
                "jsonrpc_request_id": "7"
            })
        );
    }

    /// **A field this crate removed is refused rather than ignored**, because
    /// `deny_unknown_fields` is what keeps an alias and the box from disagreeing in silence. This is
    /// the reason `PROTOCOL_VERSION` moved.
    #[test]
    fn a_removed_correlation_field_is_refused() {
        for field in [
            "conversation_id",
            "tool_call_id",
            "tool_name",
            "mcp_method",
            "linked_traceparent",
        ] {
            let raw = serde_json::json!({ field: "anything" });
            assert!(
                serde_json::from_value::<Correlation>(raw).is_err(),
                "{field} must be refused rather than dropped"
            );
        }
    }

    #[test]
    fn invalid_context_and_identifiers_cannot_reach_a_record() {
        for parent in [
            "00-00000000000000000000000000000000-0123456789abcdef-01",
            "00-0123456789abcdef0123456789abcdef-0000000000000000-01",
            "00-1-2-01",
            "0-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            "ff-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            "00-0123456789ABCDEF0123456789abcdef-0123456789abcdef-01",
        ] {
            assert!(
                !Correlation::from_headers(Some(parent), None)
                    .parent()
                    .is_valid()
            );
        }
        let correlation: Correlation = serde_json::from_value(serde_json::json!({
            "request_id": "request-7",
            "jsonrpc_request_id": "x".repeat(257)
        }))
        .unwrap();
        assert_eq!(
            correlation.attributes(),
            vec![("strands.box.request.id", "request-7".into())]
        );
        assert!(
            Correlation::from_headers(Some(PARENT), Some("vendor=value"))
                .parent()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn interleaved_operations_keep_separate_context_and_restore_the_caller() {
        let left = Correlation::default().request(Some("left"));
        let right = Correlation::default().request(Some("right"));
        let check = |expected: Correlation| async move {
            for _ in 0..8 {
                assert_eq!(Correlation::current(), expected);
                tokio::task::yield_now().await;
            }
        };
        tokio::join!(
            left.scope(check(left.clone())),
            right.scope(check(right.clone()))
        );
        assert_eq!(Correlation::current(), Correlation::default());
    }

    #[test]
    fn duplicate_or_excess_tracestate_members_do_not_discard_a_valid_parent() {
        let maximum = (0..32)
            .map(|i| format!("v{i}=1"))
            .collect::<Vec<_>>()
            .join(",");
        let too_many = format!("{maximum},extra=1");
        let valid = Correlation::from_headers(Some(PARENT), Some(&maximum));
        assert_eq!(valid.parent().trace_state().header(), maximum);
        for state in [
            "a=1,b=2,a=3",
            "a=1, a=3",
            "a==1",
            "a=",
            "=1",
            "a=\n1",
            &too_many,
        ] {
            let correlation = Correlation::from_headers(Some(PARENT), Some(state));
            assert!(correlation.parent().is_valid());
            assert!(
                correlation.parent().trace_state().header().is_empty(),
                "{state}"
            );
        }
    }

    #[test]
    fn tracestate_accepts_optional_whitespace_and_empty_members() {
        let correlation = Correlation::from_headers(Some(PARENT), Some(" \t,a=1, \t, b=  two  ,"));
        assert_eq!(correlation.parent().trace_state().header(), "a=1,b=  two");
        let empty = Correlation::from_headers(Some(PARENT), Some(" , \t,"));
        assert!(empty.parent().is_valid());
        assert!(empty.parent().trace_state().header().is_empty());
    }

    #[test]
    fn mcp_context_takes_precedence_and_links_a_distinct_transport() {
        let message = Correlation::from_mcp(
            r#"{
            "jsonrpc":"2.0","id":7,"method":"tools/call","params":{
                "name":"add","arguments":{"secret":"must-not-be-copied"},
                "_meta":{"traceparent":"00-11111111111111111111111111111111-2222222222222222-01",
                "threadId":"thread-3","callId":"call-4"}
            }
        }"#,
        )
        .with_transport(Correlation::from_headers(Some(PARENT), None));
        assert_eq!(
            message.parent().trace_id().to_string(),
            "11111111111111111111111111111111"
        );
        let attributes = message.attributes();
        assert_eq!(attributes, vec![("jsonrpc.request.id", "7".into())]);
        for key in [
            "gen_ai.conversation.id",
            "gen_ai.tool.call.id",
            "gen_ai.tool.name",
            "mcp.method.name",
            "strands.box.trace.link_traceparent",
        ] {
            assert!(
                !attributes.iter().any(|(found, _)| *found == key),
                "{key} was removed and must not return: {attributes:?}"
            );
        }
        assert!(!format!("{message:?}").contains("must-not-be-copied"));
    }
}
