//! Admission and reply bookkeeping for modern MCP requests.

use super::super::protocol_2026_07_28::{self, ModernReply, ModernRequest};
use super::*;

pub(super) async fn handle_request(
    frame: &str,
    request: &Value,
    exchange: &mut Exchange<'_>,
    policy: &PolicyEngine,
    governed: &GovernedBox,
) -> io::Result<ProgramAction> {
    if !matches!(
        exchange.connection.phase,
        McpConnectionPhase::AwaitingInitialize | McpConnectionPhase::PerRequestMetadata
    ) || exchange.connection.initialize_id.is_some()
        || request["method"] == "initialize"
    {
        return refuse(
            exchange,
            request,
            -32600,
            "modern MCP requests cannot use a legacy handshake connection",
        )
        .await;
    }
    let modern = match ModernRequest::parse(request) {
        Ok(modern) => modern,
        Err(error) => {
            exchange
                .connection
                .recorder
                .record(EffectiveDecision::enforcement_deny(
                    r#"Box::Action::"mcp:call""#,
                    exchange.running.server(),
                    "mcp-protocol",
                    &error.message,
                ));
            let response = format!("{}\n", error.response(&request["id"]));
            emit_text(exchange.frames, exchange.program, response.as_bytes(), None).await?;
            return Ok(ProgramAction::Continue);
        }
    };
    let (key, id) = require_request_id(request)?;
    if exchange.connection.in_flight.contains(&key) {
        return refuse_reused_id(exchange, Some(&id)).await;
    }
    let active = exchange.connection.modern_requests.len() - exchange.connection.cancelled.len();
    if active >= protocol_2026_07_28::MAXIMUM_PENDING {
        return refuse(
            exchange,
            request,
            -32600,
            "too many pending modern MCP requests",
        )
        .await;
    }
    let retry = modern.retry_key(request);
    let mut methods = Vec::new();
    if let Some(retry) = &retry {
        let Some(position) = exchange
            .connection
            .pending_inputs
            .iter()
            .position(|pending| pending.key == *retry)
        else {
            return refuse(
                exchange,
                request,
                -32602,
                "MCP input answers do not match a pending server request",
            )
            .await;
        };
        let pending = &exchange.connection.pending_inputs[position];
        if let Some(inputs) = request["params"]["inputResponses"].as_object() {
            for (key, answer) in inputs {
                let Some(method) = pending.methods.get(key).filter(|_| answer.is_object()) else {
                    return refuse(
                        exchange,
                        request,
                        -32602,
                        "MCP input answers contain an unknown id or invalid result",
                    )
                    .await;
                };
                methods.push(method.clone());
            }
        }
        exchange.connection.pending_inputs.remove(position);
    }
    let outcome = if modern.method == "tools/list" {
        handle_tools_list(frame, request, exchange, policy, governed).await?
    } else {
        super::handle_request(
            frame,
            request,
            &modern.method,
            exchange,
            policy,
            governed,
            &methods,
        )
        .await?
    };
    if exchange.connection.in_flight.contains(&key) {
        if modern.method != "server/discover" {
            exchange.connection.phase = McpConnectionPhase::PerRequestMetadata;
        }
        exchange.connection.modern_requests.insert(key, modern);
    }
    Ok(outcome)
}

pub(super) async fn admit_input_answers(
    methods: &[String],
    request: &Value,
    exchange: &Exchange<'_>,
    policy: &PolicyEngine,
    governed: &GovernedBox,
) -> io::Result<bool> {
    for method in methods {
        let (decision, token) = policy.decide(
            governed,
            &Principal::agent(),
            &Request::McpCall {
                server: exchange.running.server(),
                method,
                tool: None,
                prompt: None,
                uri: None,
                arguments: None,
            },
        );
        exchange
            .connection
            .recorder
            .record(EffectiveDecision::from_policy(
                r#"Box::Action::"mcp:call""#,
                format!("{}/{method}", exchange.running.server()),
                &decision,
            ));
        if !decision.is_allow() {
            refuse(exchange, request, -32001, &decision.to_string()).await?;
            return Ok(false);
        }
        token.ok_or_else(|| {
            io::Error::other("permitted MCP input answer has no committed request token")
        })?;
    }
    Ok(true)
}

async fn refuse(
    exchange: &Exchange<'_>,
    request: &Value,
    code: i32,
    reason: &str,
) -> io::Result<ProgramAction> {
    exchange
        .connection
        .recorder
        .record(EffectiveDecision::enforcement_deny(
            r#"Box::Action::"mcp:call""#,
            exchange.running.server(),
            "mcp-protocol",
            reason,
        ));
    emit_request_error(
        exchange.frames,
        exchange.program,
        request.get("id"),
        code,
        reason,
        None,
    )
    .await?;
    Ok(ProgramAction::Continue)
}

pub(super) fn accept_reply(
    key: &str,
    response: &Value,
    exchange: &mut Exchange<'_>,
) -> io::Result<bool> {
    let Some(request) = exchange.connection.modern_requests.remove(key) else {
        return Ok(true);
    };
    match request.validate_reply(response)? {
        ModernReply::LegacyProbe => {}
        ModernReply::Complete => {
            if exchange.connection.phase == McpConnectionPhase::AwaitingInitialize
                && exchange.connection.initialize_id.is_none()
            {
                exchange.connection.phase = McpConnectionPhase::PerRequestMetadata;
            }
        }
        ModernReply::InputRequired(inputs) => {
            if exchange
                .connection
                .pending_inputs
                .iter()
                .any(|previous| previous.key == inputs.key && previous.methods != inputs.methods)
            {
                return Err(invalid_data("MCP server returned ambiguous input requests"));
            }
            if exchange.connection.pending_inputs.len() >= protocol_2026_07_28::MAXIMUM_PENDING {
                exchange.connection.pending_inputs.pop_front();
            }
            exchange.connection.pending_inputs.push_back(inputs);
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn cancel_request(request: &Value, exchange: &mut Exchange<'_>) -> io::Result<()> {
    if request["method"] != "notifications/cancelled"
        || (exchange.connection.phase != McpConnectionPhase::PerRequestMetadata
            && (exchange.connection.phase != McpConnectionPhase::AwaitingInitialize
                || exchange.connection.initialize_id.is_some()
                || exchange.connection.modern_requests.is_empty()))
    {
        return Ok(());
    }
    let Some(id) = request["params"].get("requestId") else {
        return Err(invalid_data("MCP cancellation needs a requestId"));
    };
    let key = id_key(id)?;
    if exchange.connection.modern_requests.contains_key(&key)
        && !exchange.connection.cancelled.contains_key(&key)
    {
        if let Some(call) = exchange.connection.decided_calls.remove(&key) {
            record_response_leg(exchange, call)?;
        }
        if exchange.connection.cancelled.len() >= protocol_2026_07_28::MAXIMUM_CANCELLED {
            return Err(invalid_data(
                "too many retained cancelled MCP requests; reconnect",
            ));
        }
        let bytes = key.capacity() + retained_request_bytes(exchange.connection, &key);
        if exchange.connection.cancelled.values().sum::<usize>() + bytes
            > protocol_2026_07_28::MAXIMUM_CANCELLED_BYTES
        {
            return Err(invalid_data(
                "too much retained cancelled MCP request data; reconnect",
            ));
        }
        if exchange.connection.lists.remove(&key).is_some() {
            exchange.registry.list_failed(
                exchange.running.server(),
                &exchange.connection.key,
                DiscoveryFailure::CatalogCapture,
            );
        }
        exchange.connection.cancelled.insert(key, bytes);
    }
    Ok(())
}

fn retained_request_bytes(connection: &McpConnection, key: &str) -> usize {
    let mut bytes = connection.in_flight.get(key).map_or(0, String::capacity);
    if let Some((id, request)) = connection.modern_requests.get_key_value(key) {
        bytes += id.capacity() + request.method.capacity();
    }
    bytes
}
