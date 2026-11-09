use super::*;

fn modern_request(id: u64, method: &str, mut params: Value) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn modern_server(log: &Path) -> Vec<String> {
    vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!(
            r#"while IFS= read -r frame; do
printf '%s\n' "$frame" >> "$1"
id=$(printf '%s\n' "$frame" | sed -nE 's/.*"id":("[^"]*"|[0-9]+).*/\1/p')
case "$frame" in
  *'"method":"server/discover"'*)
    printf '{{"jsonrpc":"2.0","id":%s,"result":{{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{{"tools":{{}}}},"ttlMs":0,"cacheScope":"private"}}}}\n' "$id" ;;
  *'"method":"tools/list"'*)
    printf '{{"jsonrpc":"2.0","id":%s,"result":{{"resultType":"complete","tools":{SEARCH_TOOLS},"ttlMs":0,"cacheScope":"private"}}}}\n' "$id" ;;
  *'"method":"tools/call"'*)
    printf '{{"jsonrpc":"2.0","id":%s,"result":{{"resultType":"complete","content":[{{"type":"text","text":"called"}}]}}}}\n' "$id" ;;
esac
done"#
        ),
        "modern-mcp".to_string(),
        log.to_string_lossy().into_owned(),
    ]
}

#[test]
fn modern_stdio_lists_and_calls_with_or_without_discovery() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        for discover in [true, false] {
            let fixture = fixture(PERMIT_ALL_MCP);
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let (mut program, mut output) = exchange(modern_server(log.path()), &fixture).await;
            if discover {
                send(&program, modern_request(1, "server/discover", json!({}))).await;
                assert_eq!(
                    next_output(&mut output).await["result"]["supportedVersions"][0],
                    "2026-07-28"
                );
            }
            send(&program, modern_request(2, "tools/list", json!({}))).await;
            let listed = next_output(&mut output).await;
            assert_eq!(listed["result"]["tools"][0]["name"], "Search", "{listed}");
            assert_eq!(listed["result"]["cacheScope"], "private");
            assert_eq!(listed["result"]["ttlMs"], 0);
            send(
                &program,
                modern_request(
                    3,
                    "tools/call",
                    json!({"name": "Search", "arguments": {"value": "hello"}}),
                ),
            )
            .await;
            let called = next_output(&mut output).await;
            assert_eq!(called["result"]["content"][0]["text"], "called", "{called}");
            program.stop_and_wait().await.expect("stop the exchange");
            assert!(
                !read_log(log.path())
                    .iter()
                    .any(|frame| frame["method"] == "initialize")
            );
        }
    }));
}

#[test]
fn modern_metadata_is_checked_on_every_request() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        let fixture = fixture(PERMIT_ALL_MCP);
        let log = tempfile::NamedTempFile::new().expect("frame log");
        let (mut program, mut output) = exchange(modern_server(log.path()), &fixture).await;
        send(&program, modern_request(1, "tools/list", json!({}))).await;
        assert!(next_output(&mut output).await["result"]["tools"].is_array());
        let valid = modern_request(2, "tools/call", json!({"name": "Search", "arguments": {}}));
        let mut cases = Vec::new();
        let mut missing = valid.clone();
        missing["params"].as_object_mut().unwrap().remove("_meta");
        cases.push((missing, -32602));
        for field in [
            "io.modelcontextprotocol/protocolVersion",
            "io.modelcontextprotocol/clientCapabilities",
        ] {
            let mut missing = valid.clone();
            missing["params"]["_meta"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            cases.push((missing, -32602));
            let mut wrong_type = valid.clone();
            wrong_type["params"]["_meta"][field] = json!(42);
            cases.push((wrong_type, -32602));
        }
        let mut unsupported = valid.clone();
        unsupported["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] =
            json!("2099-01-01");
        cases.push((unsupported, -32022));
        let mut invalid_info = valid.clone();
        invalid_info["params"]["_meta"]["io.modelcontextprotocol/clientInfo"] =
            json!({"name": "probe"});
        cases.push((invalid_info, -32602));
        let mut fractional_id = valid.clone();
        fractional_id["id"] = json!(2.5);
        cases.push((fractional_id, -32602));
        let mut hybrid = valid.clone();
        hybrid["result"] = json!({});
        cases.push((hybrid, -32602));
        for (request, code) in cases {
            send(&program, request.clone()).await;
            let refused = next_output(&mut output).await;
            assert_eq!(refused["error"]["code"], code, "{request}: {refused}");
            if code == -32022 {
                assert_eq!(refused["error"]["data"]["supported"], json!(["2026-07-28"]));
            }
        }
        send(&program, valid).await;
        assert_eq!(
            next_output(&mut output).await["result"]["content"][0]["text"],
            "called"
        );
        program.stop_and_wait().await.expect("stop the exchange");
        assert_eq!(
            read_log(log.path())
                .iter()
                .filter(|frame| frame["method"] == "tools/call")
                .count(),
            1
        );
    }));
}

#[test]
fn modern_tool_calls_still_require_catalog_and_policy_admission() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        let fixture = fixture(&format!(
            r#"{PERMIT_ALL_MCP}
            forbid (principal, action == Box::Action::"mcp:call", resource)
            when {{ context.input has tool && context.input.tool == "Search" }};
        "#
        ));
        let log = tempfile::NamedTempFile::new().expect("frame log");
        let (mut program, mut output) = exchange(modern_server(log.path()), &fixture).await;
        send(&program, modern_request(1, "tools/list", json!({}))).await;
        assert!(next_output(&mut output).await["result"]["tools"].is_array());
        for (name, code) in [("Search", -32001), ("Unlisted", -32003)] {
            send(
                &program,
                modern_request(2, "tools/call", json!({"name": name, "arguments": {}})),
            )
            .await;
            assert_eq!(next_output(&mut output).await["error"]["code"], code);
        }
        program.stop_and_wait().await.expect("stop the exchange");
        assert!(
            !read_log(log.path())
                .iter()
                .any(|frame| frame["method"] == "tools/call")
        );
    }));
}

#[test]
fn a_failed_modern_probe_can_fall_back_to_the_legacy_handshake() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        for code in [-32601, -32602] {
            let fixture = fixture(PERMIT_ALL_MCP);
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let mut command = listing_server(log.path(), SEARCH_TOOLS, "");
            command[2] = command[2].replace("case \"$frame\" in", &format!(
                "case \"$frame\" in\n  *'\"method\":\"server/discover\"'*) printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":9,\"error\":{{\"code\":{code},\"message\":\"legacy\"}}}}' ;;"
            ));
            let (mut program, mut output) = exchange(command, &fixture).await;
            send(&program, modern_request(9, "server/discover", json!({}))).await;
            assert_eq!(next_output(&mut output).await["error"]["code"], code);
            initialize(&program, &mut output).await;
            send(&program, json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})).await;
            assert_eq!(next_output(&mut output).await["result"]["tools"][0]["name"], "Search");
            send(&program, modern_request(3, "tools/list", json!({}))).await;
            assert_eq!(next_output(&mut output).await["error"]["code"], -32600);
            program.stop_and_wait().await.expect("stop the exchange");
            assert_eq!(read_log(log.path()).iter().filter(|frame| frame["method"] == "tools/list").count(), 1);
        }
    }));
}

fn input_server(log: &Path) -> Vec<String> {
    let mut command = modern_server(log);
    command[2] = command[2].replace(
        "*'\"method\":\"tools/call\"'*)",
        r#"*'"method":"tools/call"'*)
    case "$frame" in
      *'"inputResponses"'*) ;;
      *) printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"input_required","inputRequests":{"root":{"method":"roots/list"}},"requestState":"opaque"}}\n' "$id"; continue ;;
    esac"#,
    );
    command
}

fn input_call(id: u64) -> Value {
    let mut request = modern_request(
        id,
        "tools/call",
        json!({"name": "Search", "arguments": {"value": "hello"}}),
    );
    request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({"roots": {}});
    request
}

#[test]
fn modern_input_answers_are_correlated_and_decided_before_forwarding() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        for (method, capability, deny_inputs) in [
            ("roots/list", "roots", false),
            ("roots/list", "roots", true),
            ("sampling/createMessage", "sampling", false),
            ("sampling/createMessage", "sampling", true),
            ("elicitation/create", "elicitation", false),
            ("elicitation/create", "elicitation", true),
        ] {
            let policy = if deny_inputs {
                format!(r#"{PERMIT_ALL_MCP}
                    forbid (principal, action == Box::Action::"mcp:call", resource)
                    when {{ context.input.method == "{method}" }};"#)
            } else {
                format!(r#"{PERMIT_ALL_MCP}
                    forbid (principal, action == Box::Action::"mcp:call", resource)
                    when {{ context.input has tool && context.input.tool == "Search" }}
                    when temporal {{ formerly within 3600s (Box::Action::"mcp:call"::response{{input.tool: "Search"}}) }};"#)
            };
            let fixture = fixture(&policy);
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let mut command = input_server(log.path());
            command[2] = command[2].replace("roots/list", method);
            let (mut program, mut output) = exchange(command, &fixture).await;
            send(&program, modern_request(1, "tools/list", json!({}))).await;
            assert!(next_output(&mut output).await["result"]["tools"].is_array());
            let mut initial = input_call(2);
            initial["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({capability: {}});
            send(&program, initial.clone()).await;
            let response = next_output(&mut output).await;
            assert_eq!(response["result"]["resultType"], "input_required", "{response}");
            let mut retry = initial.clone();
            retry["id"] = json!(3);
            retry["params"]["requestState"] = json!("opaque");
            retry["params"]["inputResponses"] = json!({"root": {"roots": [{"uri": "file:///secret"}]}});
            for field in ["arguments", "requestState", "inputResponses"] {
                let mut forged = retry.clone();
                forged["params"][field] = match field {
                    "arguments" => json!({"value": "different"}),
                    "requestState" => json!("forged"),
                    _ => json!({"invented": {"roots": []}}),
                };
                send(&program, forged).await;
                let response = next_output(&mut output).await;
                assert_eq!(response["error"]["code"], -32602, "{response}");
            }
            send(&program, retry.clone()).await;
            let response = next_output(&mut output).await;
            if deny_inputs {
                assert_eq!(response["error"]["code"], -32001, "{response}");
            } else {
                assert_eq!(response["result"]["resultType"], "complete", "{response}");
                send(&program, retry).await;
                assert_eq!(next_output(&mut output).await["error"]["code"], -32602, "a consumed continuation cannot be replayed");
                initial["id"] = json!(4);
                send(&program, initial).await;
                assert_eq!(next_output(&mut output).await["error"]["code"], -32001, "only the complete result counts toward the temporal limit");
            }
            program.stop_and_wait().await.expect("stop the exchange");
            assert_eq!(read_log(log.path()).iter().filter(|frame| frame["params"].get("inputResponses").is_some()).count(), usize::from(!deny_inputs));
        }
    }));
}

#[test]
fn modern_tool_arguments_still_meet_the_generated_policy_action() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        let fixture = fixture(&format!(
            r#"{PERMIT_ALL_MCP}
            forbid (principal, action == issues_mcp::Action::"Search", resource)
            when {{ context.input has value && context.input.value == "blocked" }};"#
        ));
        let log = tempfile::NamedTempFile::new().expect("frame log");
        let (mut program, mut output) = exchange(modern_server(log.path()), &fixture).await;
        send(&program, modern_request(1, "tools/list", json!({}))).await;
        assert!(next_output(&mut output).await["result"]["tools"].is_array());
        for value in ["allowed", "blocked"] {
            send(
                &program,
                modern_request(
                    2,
                    "tools/call",
                    json!({"name": "Search", "arguments": {"value": value}}),
                ),
            )
            .await;
            let response = next_output(&mut output).await;
            if value == "allowed" {
                assert_eq!(response["result"]["resultType"], "complete");
            } else {
                assert_eq!(response["error"]["code"], -32001, "{response}");
            }
        }
        program.stop_and_wait().await.expect("stop the exchange");
        let calls: Vec<Value> = read_log(log.path())
            .into_iter()
            .filter(|frame| frame["method"] == "tools/call")
            .collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["params"]["arguments"]["value"], "allowed");
    }));
}

#[test]
fn malformed_modern_lists_never_become_an_accepted_catalog() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        for (original, invalid) in [
            (r#""ttlMs":0"#, r#""ttlMs":-1"#),
            (r#""cacheScope":"private""#, r#""cacheScope":"shared""#),
            (
                r#""resultType":"complete""#,
                r#""resultType":"input_required""#,
            ),
        ] {
            let fixture = fixture(PERMIT_ALL_MCP);
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let mut command = modern_server(log.path());
            command[2] = command[2].replace(original, invalid);
            let (mut program, mut output) = exchange(command, &fixture).await;
            send(&program, modern_request(1, "tools/list", json!({}))).await;
            assert_eq!(next_output(&mut output).await["error"]["code"], -32603);
            assert!(
                fixture
                    .registry
                    .require_listed("issues-mcp", "Search")
                    .is_err()
            );
            assert!(program.join().await.is_err());
        }
    }));
}

#[test]
fn modern_connections_refuse_legacy_message_directions_and_handshakes() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        let fixture = fixture(PERMIT_ALL_MCP);
        let log = tempfile::NamedTempFile::new().expect("frame log");
        let (mut program, mut output) = exchange(modern_server(log.path()), &fixture).await;
        send(&program, modern_request(1, "tools/list", json!({}))).await;
        assert!(next_output(&mut output).await["result"]["tools"].is_array());
        send(&program, json!({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}})).await;
        assert_eq!(next_output(&mut output).await["error"]["code"], -32600);
        send(&program, json!({"jsonrpc": "2.0", "id": 3, "result": {"roots": []}})).await;
        assert!(program.join().await.unwrap_err().to_string().contains("cannot send JSON-RPC responses"));
        assert_eq!(read_log(log.path()).len(), 1);

        let fixture = super::fixture(PERMIT_ALL_MCP);
        let log = tempfile::NamedTempFile::new().expect("frame log");
        let mut command = modern_server(log.path());
        command[2] = command[2].replace(
            "*'\"method\":\"tools/call\"'*)",
            "*'\"method\":\"tools/call\"'*) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":\"server-input\",\"method\":\"roots/list\"}'; continue",
        );
        let (mut program, mut output) = exchange(command, &fixture).await;
        send(&program, modern_request(1, "tools/list", json!({}))).await;
        assert!(next_output(&mut output).await["result"]["tools"].is_array());
        send(&program, input_call(2)).await;
        assert!(program.join().await.unwrap_err().to_string().contains("cannot send JSON-RPC requests"));
    }));
}

#[test]
fn a_pending_probe_does_not_prevent_legacy_timeout_fallback() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        let fixture = fixture(PERMIT_ALL_MCP);
        let log = tempfile::NamedTempFile::new().expect("frame log");
        let (mut program, mut output) =
            exchange(listing_server(log.path(), SEARCH_TOOLS, ""), &fixture).await;
        send(&program, modern_request(9, "server/discover", json!({}))).await;
        initialize(&program, &mut output).await;
        send(
            &program,
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        )
        .await;
        assert_eq!(
            next_output(&mut output).await["result"]["tools"][0]["name"],
            "Search"
        );
        program.stop_and_wait().await.expect("stop the exchange");
    }));
}

#[test]
fn modern_cancellation_hides_late_replies_but_still_records_their_response() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        let late_complete = r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[]}}"#;
        let late_input = r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"input_required","inputRequests":{"root":{"method":"roots/list"}},"requestState":"opaque"}}"#;
        for (late_reply, counts) in [(late_complete, true), (late_input, false)] {
            let fixture = fixture(&format!(r#"{PERMIT_ALL_MCP}
                forbid (principal, action == Box::Action::"mcp:call", resource)
                when {{ context.input has tool && context.input.tool == "Search" }}
                when temporal {{ formerly within 3600s (Box::Action::"mcp:call"::response{{input.tool: "Search"}}) }};"#));
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let mut command = modern_server(log.path());
            // The server ignores the cancellation: it answers the cancelled call late, just
            // before it answers the ping, so the broker reads the late reply first.
            command[2] = command[2].replace("case \"$frame\" in", &format!(r#"case "$frame" in
  *'"method":"tools/call"'*'"value":"wait"'*) continue ;;
  *'"method":"ping"'*) printf '%s\n' '{late_reply}' '{{"jsonrpc":"2.0","id":3,"result":{{"resultType":"complete"}}}}'; continue ;;"#));
            let (mut program, mut output) = exchange(command, &fixture).await;
            send(&program, modern_request(1, "tools/list", json!({}))).await;
            assert!(next_output(&mut output).await["result"]["tools"].is_array());
            let mut call = input_call(2);
            call["params"]["arguments"] = json!({"value": "wait"});
            send(&program, call.clone()).await;
            send(&program, json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 2}})).await;
            send(&program, call).await;
            assert!(next_output(&mut output).await["error"].is_object(), "cancelled id remains reserved");
            send(&program, modern_request(3, "ping", json!({}))).await;
            assert_eq!(next_output(&mut output).await["id"], 3, "cancelled response never reaches the client");
            send(&program, modern_request(4, "tools/call", json!({"name": "Search", "arguments": {"value": "continue"}}))).await;
            let response = next_output(&mut output).await;
            assert_eq!(response["id"], 4, "{response}");
            if counts {
                assert_eq!(response["error"]["code"], -32001, "a cancelled call that ran records its response: {response}");
            } else {
                assert_eq!(response["result"]["resultType"], "complete", "an incomplete cancelled call records no response: {response}");
            }
            program.stop_and_wait().await.expect("stop the exchange");
            assert_eq!(read_log(log.path()).iter().filter(|frame| frame["method"] == "tools/call").count(), 1 + usize::from(!counts));
        }
    }));
}

#[test]
fn modern_pending_request_and_continuation_limits_are_enforced() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        for (continuations, identical) in [(false, false), (true, false), (true, true)] {
            let fixture = fixture(PERMIT_ALL_MCP);
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let mut command = input_server(log.path());
            if !continuations {
                command[2] = command[2].replace(
                    "case \"$frame\" in",
                    "case \"$frame\" in\n *'\"method\":\"tools/call\"'*) continue ;;",
                );
            }
            let (mut program, mut output) = exchange(command, &fixture).await;
            send(&program, modern_request(1, "tools/list", json!({}))).await;
            assert!(next_output(&mut output).await["result"]["tools"].is_array());
            for id in 2..=66 {
                let mut call = input_call(id);
                if !identical {
                    call["params"]["arguments"]["value"] = json!(id.to_string());
                }
                send(&program, call).await;
                if continuations || id == 66 {
                    let response = next_output(&mut output).await;
                    if id == 66 && !continuations {
                        assert!(
                            response["error"]["message"]
                                .as_str()
                                .unwrap()
                                .contains("too many pending"),
                            "{response}"
                        );
                    } else {
                        assert_eq!(response["result"]["resultType"], "input_required");
                    }
                }
            }
            wait_for_logged(log.path(), |frame| {
                frame["id"] == if continuations { 66 } else { 65 }
            })
            .await;
            let _ = program.stop_and_wait().await;
            assert_eq!(
                read_log(log.path())
                    .iter()
                    .filter(|frame| frame["method"] == "tools/call")
                    .count(),
                if continuations { 65 } else { 64 }
            );
        }
    }));
}

#[test]
fn modern_input_requests_require_capabilities_and_unambiguous_methods() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        for conflict in [false, true] {
            let fixture = fixture(PERMIT_ALL_MCP);
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let mut command = input_server(log.path());
            if conflict {
                command[2] = command[2].replace("case \"$frame\" in", r#"case "$frame" in
  *'"id":3'*'"method":"tools/call"'*) printf '{"jsonrpc":"2.0","id":3,"result":{"resultType":"input_required","inputRequests":{"root":{"method":"sampling/createMessage"}},"requestState":"opaque"}}\n'; continue ;;"#);
            }
            let (mut program, mut output) = exchange(command, &fixture).await;
            send(&program, modern_request(1, "tools/list", json!({}))).await;
            assert!(next_output(&mut output).await["result"]["tools"].is_array());
            let mut call = input_call(2);
            call["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = if conflict { json!({"roots": {}, "sampling": {}}) } else { json!({}) };
            send(&program, call.clone()).await;
            if conflict {
                assert_eq!(next_output(&mut output).await["result"]["resultType"], "input_required");
                call["id"] = json!(3);
                send(&program, call).await;
            }
            let response = next_output(&mut output).await;
            assert_eq!(response["error"]["code"], -32603, "{response}");
            assert!(response["error"]["message"].as_str().unwrap().contains(if conflict { "ambiguous" } else { "capabilities" }), "{response}");
            let _ = program.stop_and_wait().await;
        }
    }));
}

#[test]
fn refused_outer_retry_does_not_decide_its_input_answers() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        let policy = format!(r#"{PERMIT_ALL_MCP}
            forbid (principal, action == Box::Action::"mcp:call", resource)
            when {{ context.input has tool && context.input.tool == "Search" }}
            when temporal {{ formerly within 3600s (Box::Action::"mcp:call"::request{{input.method: "prompts/list"}}) }};"#);
        let fixture = fixture(&policy);
        let log = tempfile::NamedTempFile::new().unwrap();
        let mut command = input_server(log.path());
        command[2] = command[2].replace("case \"$frame\" in", r#"case "$frame" in
  *'"method":"prompts/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","prompts":[],"ttlMs":0,"cacheScope":"private"}}\n' "$id"; continue ;;"#);
        let (mut program, mut output, recorder) =
            recorded_exchange(command, &fixture).await;
        send(&program, modern_request(1, "tools/list", json!({}))).await;
        assert!(next_output(&mut output).await["result"]["tools"].is_array());
        send(&program, input_call(2)).await;
        assert_eq!(next_output(&mut output).await["result"]["resultType"], "input_required");
        send(&program, modern_request(10, "prompts/list", json!({}))).await;
        assert!(next_output(&mut output).await["result"]["prompts"].is_array());
        let mut retry = input_call(3);
        retry["params"]["requestState"] = json!("opaque");
        retry["params"]["inputResponses"] = json!({"root": {"roots": []}});
        send(&program, retry).await;
        assert_eq!(next_output(&mut output).await["error"]["code"], -32001);
        assert!(!recorder.recorded().iter().any(|decision| decision.parts().1.ends_with("/roots/list")),
            "a refused outer retry must not consume an input-answer decision");
        program.stop_and_wait().await.unwrap();
        assert!(!read_log(log.path()).iter().any(|frame| frame["params"].get("inputResponses").is_some()));
    }));
}

#[test]
fn identical_continuations_each_keep_one_retry() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        for state in [true, false] {
            let fixture = fixture(PERMIT_ALL_MCP);
            let log = tempfile::NamedTempFile::new().unwrap();
            let mut command = input_server(log.path());
            if !state {
                command[2] = command[2].replace(",\"requestState\":\"opaque\"", "");
            }
            let (mut program, mut output) = exchange(command, &fixture).await;
            send(&program, modern_request(1, "tools/list", json!({}))).await;
            assert!(next_output(&mut output).await["result"]["tools"].is_array());
            for id in [2, 3] {
                send(&program, input_call(id)).await;
                assert_eq!(
                    next_output(&mut output).await["result"]["resultType"],
                    "input_required"
                );
            }
            for id in [4, 5, 6] {
                let mut retry = input_call(id);
                if state {
                    retry["params"]["requestState"] = json!("opaque");
                }
                retry["params"]["inputResponses"] = json!({"root": {"roots": []}});
                send(&program, retry).await;
                let response = next_output(&mut output).await;
                if id < 6 {
                    assert_eq!(response["result"]["resultType"], "complete", "{response}");
                } else {
                    assert_eq!(response["error"]["code"], -32602, "{response}");
                }
            }
            program.stop_and_wait().await.unwrap();
            assert_eq!(
                read_log(log.path())
                    .iter()
                    .filter(|frame| frame["params"].get("inputResponses").is_some())
                    .count(),
                2
            );
        }
    }));
}

#[test]
fn legacy_parameter_names_and_cancellation_keep_their_existing_behavior() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        let fixture = fixture(PERMIT_ALL_MCP);
        let log = tempfile::NamedTempFile::new().unwrap();
        let (mut program, mut output) = exchange(listing_server(log.path(), SEARCH_TOOLS, ":"), &fixture).await;
        initialize(&program, &mut output).await;
        send(&program, json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{}})).await;
        send(&program, json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"requestState":"custom","inputResponses":{}}})).await;
        assert!(next_output(&mut output).await["result"]["tools"].is_array());
        program.stop_and_wait().await.unwrap();
        let frames = read_log(log.path());
        assert!(frames.iter().any(|frame| frame["method"] == "notifications/cancelled"));
        assert!(frames.iter().any(|frame| frame["params"]["requestState"] == "custom"));
    }));
}

#[test]
fn continuation_lifecycle_evicts_oldest_without_closing_the_connection() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        let fixture = fixture(PERMIT_ALL_MCP);
        let log = tempfile::NamedTempFile::new().unwrap();
        let mut command = input_server(log.path());
        command[2] = command[2].replace(
            "*'\"inputResponses\"'*) ;;",
            "*'\"inputResponses\"'*|*'\"value\":\"normal\"'*) ;;",
        );
        let (mut program, mut output) = exchange(command, &fixture).await;
        send(&program, modern_request(1, "tools/list", json!({}))).await;
        assert!(next_output(&mut output).await["result"]["tools"].is_array());
        for id in 2..=66 {
            let mut call = input_call(id);
            call["params"]["arguments"]["value"] = json!(id.to_string());
            send(&program, call).await;
            let response = next_output(&mut output).await;
            assert_eq!(
                response["result"]["resultType"], "input_required",
                "{response}"
            );
        }
        for (id, original, expected) in [(100, 2, false), (101, 3, true)] {
            let mut retry = input_call(id);
            retry["params"]["arguments"]["value"] = json!(original.to_string());
            retry["params"]["requestState"] = json!("opaque");
            retry["params"]["inputResponses"] = json!({"root": {"roots": []}});
            send(&program, retry).await;
            let response = next_output(&mut output).await;
            if expected {
                assert_eq!(response["result"]["resultType"], "complete", "{response}");
            } else {
                assert_eq!(response["error"]["code"], -32602, "{response}");
            }
        }
        send(
            &program,
            modern_request(
                102,
                "tools/call",
                json!({"name":"Search","arguments":{"value":"normal"}}),
            ),
        )
        .await;
        assert_eq!(
            next_output(&mut output).await["result"]["resultType"],
            "complete"
        );
        program.stop_and_wait().await.unwrap();
    }));
}

#[test]
fn continuation_lifecycle_releases_a_policy_denied_retry() {
    let (runtime, local) = local_runtime();
    runtime.block_on(local.run_until(async {
        let policy = format!(
            r#"{PERMIT_ALL_MCP}
            forbid (principal, action == Box::Action::"mcp:call", resource)
            when {{ context.input.method == "roots/list" }};"#
        );
        let fixture = fixture(&policy);
        let log = tempfile::NamedTempFile::new().unwrap();
        let (mut program, mut output) = exchange(input_server(log.path()), &fixture).await;
        send(&program, modern_request(1, "tools/list", json!({}))).await;
        assert!(next_output(&mut output).await["result"]["tools"].is_array());
        send(&program, input_call(2)).await;
        assert_eq!(
            next_output(&mut output).await["result"]["resultType"],
            "input_required"
        );
        let mut retry = input_call(3);
        retry["params"]["requestState"] = json!("opaque");
        retry["params"]["inputResponses"] = json!({"root":{"roots":[]}});
        send(&program, retry.clone()).await;
        assert_eq!(next_output(&mut output).await["error"]["code"], -32001);
        retry["id"] = json!(4);
        send(&program, retry).await;
        assert_eq!(next_output(&mut output).await["error"]["code"], -32602);
        program.stop_and_wait().await.unwrap();
    }));
}
