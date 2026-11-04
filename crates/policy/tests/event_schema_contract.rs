//! Check reserved history fields from public producers against the declared event schema.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use dogwood_language::{
    Event, EventFieldType, LoweredPolicySet, PolicySchema, ServiceSchema, Value,
};
use dogwood_local_engine::{DurableLog, Record};
use policy::{
    Delivery, FsOperation, FsResult, GovernedBox, Outcome, PathResolver, Policy, PolicyEngine,
    Principal, Request, compose_action_schema, event_schema_source, generate_mcp_schema,
};

fn events(path: &Path) -> Vec<Event> {
    let log = DurableLog::open(path).expect("history opens");
    let mut events = Vec::new();
    log.scan_from(0, |_, bytes| {
        if let Record::Event(event) = Record::decode(bytes).expect("record decodes") {
            events.push(event);
        }
    })
    .expect("history scans");
    events
}

fn record_operation(
    engine: &PolicyEngine,
    request: Request<'_>,
    outcome: Outcome<'_>,
    identifiers: &mut Vec<String>,
) {
    let governed = GovernedBox::assigned("schema-contract");
    let principal = Principal::agent();
    let (decision, request_id) = engine.decide(&governed, &principal, &request);
    assert!(
        decision.is_allow(),
        "fixture request must reach its producer: {decision:?}"
    );
    let request_id = request_id.expect("a submitted request has an identifier");
    identifiers.extend([
        request_id.as_str().to_string(),
        request_id.as_str().to_string(),
    ]);
    engine
        .record(&governed, &principal, &request_id, &outcome)
        .expect("outcome records");
}

#[test]
fn every_public_producer_populates_the_reserved_fields_declared_by_its_schema() {
    let tools = r#"{"result":{"tools":[{"name":"lookup","description":"Look up a value","inputSchema":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}}]}}"#;
    let generated = generate_mcp_schema("catalog", tools).expect("tool schema generates");
    let actions = compose_action_schema(&[("catalog", &generated)]).expect("schemas compose");
    let service = ServiceSchema::builder()
        .event_schema_str(event_schema_source())
        .build()
        .expect("event schema parses");
    let action_schema = PolicySchema::from_cedarschema_str(&actions).expect("action schema parses");
    let lowered = LoweredPolicySet::from_str(
        "permit(principal, action, resource);",
        &service,
        &action_schema,
    )
    .expect("event schema derives");
    let signatures: Vec<_> = lowered.event_signatures().collect();
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let engine = PolicyEngine::open_with_mcp_schemas(
        vec![Policy {
            origin: PathBuf::from("schema-contract.dw"),
            text: r#"permit(principal, action, resource);
                forbid(principal, action == Box::Action::"http:request", resource)
                when { context.input.host == "blocked.example" };"#
                .to_string(),
        }],
        &[generated],
        &path,
    )
    .expect("authority opens");
    let mut identifiers = Vec::new();
    let approved = PathResolver::over([PathBuf::from("/workspace")])
        .expect("root is absolute")
        .approve_virtual(Path::new("/workspace/file"))
        .expect("fixture path resolves");
    // All operation mappings are exercised, even when several share one raised action.
    for operation in [
        FsOperation::ReadContent,
        FsOperation::ReadMetadata,
        FsOperation::Enumerate,
        FsOperation::ExecFile,
        FsOperation::ReadLink,
        FsOperation::ChangeDir,
        FsOperation::WriteContent,
        FsOperation::CreateDir,
        FsOperation::SetPermissions,
        FsOperation::Symlink,
        FsOperation::RemoveFile,
        FsOperation::RemoveDir,
        FsOperation::Rename,
        FsOperation::Other,
    ] {
        for result in [
            FsResult::Completed,
            FsResult::DescriptorIssued,
            FsResult::Indeterminate,
            FsResult::Failed,
        ] {
            record_operation(
                &engine,
                Request::Fs {
                    path: &approved,
                    operation,
                },
                Outcome::Fs {
                    path: Path::new("/workspace/file"),
                    operation,
                    result,
                },
                &mut identifiers,
            );
        }
    }
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    for connected in [true, false] {
        record_operation(
            &engine,
            Request::Connect {
                host: "api.example.com",
                ip: Some(ip),
                port: 443,
            },
            Outcome::Connect {
                host: "api.example.com",
                port: 443,
                address: SocketAddr::new(ip, 443),
                connected,
            },
            &mut identifiers,
        );
    }
    for delivery in [
        Delivery::Completed { bytes: 5 },
        Delivery::Partial { accepted_bytes: 3 },
        Delivery::Indeterminate { accepted_bytes: 2 },
        Delivery::Failed,
    ] {
        record_operation(
            &engine,
            Request::Http {
                host: "api.example.com",
                port: 443,
                method: "POST",
                path: "/upload",
                body_bytes: 5,
                intercepted: true,
            },
            Outcome::Http {
                host: "api.example.com",
                port: 443,
                method: "POST",
                path: "/upload",
                delivery,
                status: None,
                intercepted: true,
            },
            &mut identifiers,
        );
    }
    let words = vec!["value".to_string()];
    record_operation(
        &engine,
        Request::ShellExec {
            command: "echo value",
            program: "echo",
            args: &words,
            cwd: "/workspace",
        },
        Outcome::ShellRun {
            command: "echo value",
            program: "echo",
            args: &words,
            cwd: "/workspace",
            status: 0,
        },
        &mut identifiers,
    );
    let credentials = vec!["/workspace/credentials".to_string()];
    record_operation(
        &engine,
        Request::ShellSpawn {
            command: "tool value",
            program: "tool",
            program_path: "/usr/bin/tool",
            credential_reads: &credentials,
            args: &words,
            cwd: "/workspace",
        },
        Outcome::ShellSpawn {
            command: "tool value",
            program: "tool",
            program_path: "/usr/bin/tool",
            credential_reads: &credentials,
            args: &words,
            cwd: "/workspace",
            status: 42,
        },
        &mut identifiers,
    );
    for (method, tool, prompt, uri) in [
        ("tools/call", Some("lookup"), None, None),
        ("prompts/get", None, Some("summarize"), None),
        ("resources/read", None, None, Some("file:///workspace/file")),
        ("tools/list", None, None, None),
    ] {
        record_operation(
            &engine,
            Request::McpCall {
                server: "catalog",
                method,
                tool,
                prompt,
                uri,
                arguments: None,
            },
            Outcome::Mcp {
                server: "catalog",
                method,
                tool,
                prompt,
                uri,
            },
            &mut identifiers,
        );
    }
    // Typed tools use a separate raw-input builder. Their decision event is currently the
    // only server-namespaced producer; completions belong to the coarse mcp:call admission.
    let arguments = serde_json::json!({"query": "value"});
    let (decision, request_id) = engine.decide(
        &GovernedBox::assigned("schema-contract"),
        &Principal::agent(),
        &Request::McpCall {
            server: "catalog",
            method: "tools/call",
            tool: Some("lookup"),
            prompt: None,
            uri: None,
            arguments: Some(&arguments),
        },
    );
    assert!(
        decision.is_allow(),
        "typed request reaches its producer: {decision:?}"
    );
    identifiers.push(
        request_id
            .expect("typed request records")
            .as_str()
            .to_string(),
    );
    let (decision, request_id) = engine.decide(
        &GovernedBox::assigned("schema-contract"),
        &Principal::agent(),
        &Request::Http {
            host: "blocked.example",
            port: 443,
            method: "POST",
            path: "/upload",
            body_bytes: 5,
            intercepted: true,
        },
    );
    assert!(
        !decision.is_allow(),
        "the denied request still enters history"
    );
    identifiers.push(
        request_id
            .expect("denied submitted request records")
            .as_str()
            .to_string(),
    );
    drop(engine);

    let stored = events(&path);
    assert_eq!(
        stored.len(),
        identifiers.len(),
        "every admission and outcome records once"
    );
    for (event, identifier) in stored.iter().zip(&identifiers) {
        assert!(!identifier.is_empty());
        assert_eq!(
            event.field_path(&["requestId".to_string()]),
            Some(&Value::String(identifier.clone())),
            "each outcome must retain its own request's token"
        );
        let signature = signatures
            .iter()
            .find(|signature| {
                signature.namespace() == event.namespace()
                    && signature.action() == event.action()
                    && signature.kind() == event.kind()
            })
            .expect("every emitted event belongs to the declared schema");
        // Reserved fields are all declared leaves outside the action's input/output records.
        // Derive this list; a new declaration must fail here until every producer supplies it.
        for declared in signature
            .fields()
            .filter(|field| !matches!(field.path()[0].as_str(), "input" | "output"))
        {
            let field = declared.path();
            let ty = declared.field_type();
            let value = event.field_path(field).unwrap_or_else(|| {
                panic!(
                    "{}::{} lacks declared reserved field {}",
                    event.action(),
                    event.kind(),
                    field.join(".")
                )
            });
            let conforms = match (ty, value) {
                (EventFieldType::Cedar(ty), Value::String(_)) => ty == "String",
                (EventFieldType::Cedar(ty), Value::Int(_)) => ty == "Long",
                (EventFieldType::Cedar(ty), Value::Bool(_)) => ty == "Boolean",
                (EventFieldType::EntityTypes(types), Value::Entity { ty, .. }) => {
                    let namespace = &signature.namespace()[..signature.namespace().len() - 1];
                    types.iter().any(|declared| {
                        declared == ty || format!("{}::{declared}", namespace.join("::")) == *ty
                    })
                }
                _ => false,
            };
            assert!(
                conforms,
                "{}::{} field {} must match {ty:?}, got {value:?}",
                event.action(),
                event.kind(),
                field.join(".")
            );
        }
    }
    let emitted: BTreeSet<_> = stored
        .iter()
        .map(|event| {
            (
                event.namespace().to_vec(),
                event.action().to_string(),
                event.kind().to_string(),
            )
        })
        .collect();
    let expected: BTreeSet<_> = signatures
        .iter()
        .filter(|signature| {
            if signature.kind() == "request" {
                return true;
            }
            if signature.namespace() != ["Box", "Action"] {
                return false;
            }
            match signature.kind() {
                "response" => true,
                // These actions can fail before an effect. Shell exit errors and MCP server errors
                // are completed responses, so those declared error kinds have no public producer.
                "error" => {
                    signature.action().starts_with("fs:")
                        || matches!(signature.action(), "net:connect" | "http:request")
                }
                other => panic!("new event kind {other} needs producer coverage"),
            }
        })
        .map(|signature| {
            (
                signature.namespace().to_vec(),
                signature.action().to_string(),
                signature.kind().to_string(),
            )
        })
        .collect();
    assert_eq!(
        emitted, expected,
        "every declared action needs public producer coverage"
    );
    let requests: Vec<_> = stored
        .iter()
        .filter(|event| event.kind() == "request")
        .map(|event| {
            event
                .field_path(&["requestId".to_string()])
                .expect("request has identifier")
        })
        .collect();
    for (index, identifier) in requests.iter().enumerate() {
        assert!(
            !requests[..index].contains(identifier),
            "unrelated requests must never share an identifier"
        );
    }
}
