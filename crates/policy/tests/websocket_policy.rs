#![cfg(feature = "egress-adapter")]

#[path = "support/history.rs"]
mod history;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dogwood_language::Value;
use egress_gateway::{EffectAttempt, EffectInterceptor, EffectOutcome, WebSocketOpcode};
use policy::{
    EgressPolicyInterceptor, FsOperation, FsResult, GovernedBox, Outcome, PathResolver, Policy,
    PolicyEngine, Principal, Request,
};

const SAMPLE: &str = r#"
@id("github_read")
permit (principal, action == Box::Action::"http:request", resource)
when { context.input.host == "api.github.com" && context.input.method == "GET" };
@id("none_after_key")
@description("Nothing leaves after the SSH key is read.")
forbid (principal, action in [Box::Action::"http:request", Box::Action::"websocket:send"], resource)
when temporal {
  formerly within 24h (
    Box::Action::"fs:read"::response{ input.path: "~/.ssh/id_ed25519",
                                      input.operation: Box::FsReadOperation::"read_content" }
  )
};
@id("realtime")
permit (principal, action == Box::Action::"http:request", resource)
when { context.input.host == "realtime.example.com" && context.input.path == "/v1/realtime" &&
       context.input.upgrade == "websocket" };
@id("realtime_messages")
permit (principal, action in [Box::Action::"websocket:send", Box::Action::"websocket:receive"], resource)
when { context.input.host == "realtime.example.com" && context.input.path == "/v1/realtime" &&
       context.input.body_bytes <= 1048576 };
@id("websocket_budget")
@description("At most 10 MiB sent over WebSockets in 10 minutes.")
forbid (principal, action == Box::Action::"websocket:send", resource)
when temporal {
  exists (total: Long). (
    (sum b for (b: Long), (t: Timepoint). where (
      formerly within 10m (
        Box::Action::"websocket:send"::response{ input.body_bytes: b } && tp(t)
      )
    )) == total && total >= 10485760
  )
};
"#;

const MIB: usize = 1_048_576;
const REALTIME: &str = "realtime.example.com";

struct Fixture {
    history: tempfile::TempDir,
    policy: Arc<PolicyEngine>,
    egress: Arc<dyn EffectInterceptor>,
}

impl Fixture {
    fn open() -> Self {
        let history = tempfile::tempdir().expect("history directory");
        let sources = [
            SAMPLE,
            r#"permit (principal, action == Box::Action::"fs:read", resource);"#,
        ]
        .map(|text| Policy {
            origin: PathBuf::from("policy.dw"),
            text: text.to_string(),
        });
        let policy = Arc::new(
            PolicyEngine::open(sources.into(), &history.path().join("dogwood.redb"))
                .expect("the sample policy loads"),
        );
        let egress = EgressPolicyInterceptor::into_handle(
            Arc::clone(&policy),
            Principal::agent(),
            GovernedBox::assigned("websocket-test"),
        );
        Self {
            history,
            policy,
            egress,
        }
    }

    fn admits(&self, attempt: &EffectAttempt<'_>) -> bool {
        self.egress.intercept(attempt).is_ok()
    }

    fn deliver(&self, attempt: &EffectAttempt<'_>, outcome: EffectOutcome) {
        self.egress
            .intercept(attempt)
            .expect("the attempt is admitted")
            .record_outcome(outcome)
            .expect("the outcome records");
    }

    fn read_the_key(&self) {
        let home = PathBuf::from("/home/agent");
        let key = PathResolver::over([home.clone()])
            .expect("an absolute root")
            .reporting_under(home)
            .approve_virtual(Path::new("/home/agent/.ssh/id_ed25519"))
            .expect("the key is under the home");
        let (governed, principal) = (GovernedBox::assigned("websocket-test"), Principal::agent());
        let operation = FsOperation::ReadContent;
        let (decision, request_id) = self.policy.decide(
            &governed,
            &principal,
            &Request::Fs {
                path: &key,
                operation,
            },
        );
        assert!(decision.is_allow(), "{decision:?}");
        self.policy
            .record(
                &governed,
                &principal,
                &request_id.expect("a decided request has an id"),
                &Outcome::Fs {
                    path: Path::new(key.reported().as_ref()),
                    operation,
                    result: FsResult::Completed,
                },
            )
            .expect("the read records");
    }
}

fn handshake<'a>(host: &'a str, path: &'a str, upgrade: &'a str) -> EffectAttempt<'a> {
    EffectAttempt::HttpRequest {
        host,
        port: 443,
        method: "GET",
        path,
        body_bytes: 0,
        intercepted: true,
        mcp: None,
        upgrade,
    }
}

fn send(host: &str, opcode: WebSocketOpcode, body_bytes: usize) -> EffectAttempt<'_> {
    EffectAttempt::WebSocketSend {
        host,
        port: 443,
        path: "/v1/realtime",
        opcode,
        body_bytes,
    }
}

fn receive(host: &str, opcode: WebSocketOpcode, body_bytes: usize) -> EffectAttempt<'_> {
    EffectAttempt::WebSocketReceive {
        host,
        port: 443,
        path: "/v1/realtime",
        opcode,
        body_bytes,
    }
}

#[test]
fn a_get_permit_admits_a_handshake_head_and_no_message() {
    let fixture = Fixture::open();
    let github = "api.github.com";
    assert!(fixture.admits(&handshake(github, "/events", "websocket")));
    assert!(!fixture.admits(&send(github, WebSocketOpcode::Text, 1)));
    assert!(!fixture.admits(&receive(github, WebSocketOpcode::Text, 1)));
}

#[test]
fn a_websocket_needs_the_handshake_permit_and_a_message_permit_in_each_direction() {
    let fixture = Fixture::open();
    assert!(!fixture.admits(&handshake(REALTIME, "/v1/realtime", "")));
    assert!(fixture.admits(&handshake(REALTIME, "/v1/realtime", "websocket")));
    for opcode in [WebSocketOpcode::Text, WebSocketOpcode::Binary] {
        assert!(fixture.admits(&send(REALTIME, opcode, MIB)));
        assert!(fixture.admits(&receive(REALTIME, opcode, MIB)));
        assert!(!fixture.admits(&send(REALTIME, opcode, MIB + 1)));
        assert!(!fixture.admits(&receive(REALTIME, opcode, MIB + 1)));
    }
    for opcode in [
        WebSocketOpcode::Ping,
        WebSocketOpcode::Pong,
        WebSocketOpcode::Close,
    ] {
        assert!(fixture.admits(&send(REALTIME, opcode, 9)));
        assert!(fixture.admits(&receive(REALTIME, opcode, 9)));
    }
}

#[test]
fn the_guard_stops_the_next_message_out_and_lets_the_server_send() {
    let fixture = Fixture::open();
    assert!(fixture.admits(&send(REALTIME, WebSocketOpcode::Text, 53)));
    fixture.read_the_key();
    assert!(!fixture.admits(&send(REALTIME, WebSocketOpcode::Binary, 6400)));
    assert!(!fixture.admits(&handshake("api.github.com", "/events", "")));
    assert!(fixture.admits(&receive(REALTIME, WebSocketOpcode::Text, 26)));
}

#[test]
fn the_budget_sums_the_delivered_bytes_of_sent_messages_only() {
    let fixture = Fixture::open();
    let message = send(REALTIME, WebSocketOpcode::Binary, MIB);
    for _ in 0..10 {
        fixture.deliver(
            &receive(REALTIME, WebSocketOpcode::Binary, MIB),
            EffectOutcome::Completed(MIB),
        );
    }
    fixture.deliver(
        &message,
        EffectOutcome::Failed {
            accepted_bytes: 0,
            error_kind: std::io::ErrorKind::ConnectionReset,
        },
    );
    for _ in 0..9 {
        fixture.deliver(&message, EffectOutcome::Completed(MIB));
    }
    fixture.deliver(
        &message,
        EffectOutcome::Partial {
            accepted_bytes: MIB - 1,
            error_kind: std::io::ErrorKind::ConnectionReset,
        },
    );
    assert!(fixture.admits(&message), "1 byte under the budget");
    fixture.deliver(
        &send(REALTIME, WebSocketOpcode::Pong, 1),
        EffectOutcome::Completed(1),
    );
    assert!(!fixture.admits(&message), "the budget is spent");
    assert!(fixture.admits(&receive(REALTIME, WebSocketOpcode::Binary, MIB)));
}

#[test]
fn each_decision_records_the_events_the_design_names() {
    let fixture = Fixture::open();
    fixture.deliver(
        &handshake(REALTIME, "/v1/realtime", "websocket"),
        EffectOutcome::Replied {
            accepted_bytes: 0,
            status: 101,
        },
    );
    fixture.deliver(
        &send(REALTIME, WebSocketOpcode::Text, 53),
        EffectOutcome::Partial {
            accepted_bytes: 20,
            error_kind: std::io::ErrorKind::BrokenPipe,
        },
    );
    fixture.deliver(
        &receive(REALTIME, WebSocketOpcode::Close, 2),
        EffectOutcome::Failed {
            accepted_bytes: 0,
            error_kind: std::io::ErrorKind::BrokenPipe,
        },
    );
    let Fixture {
        history,
        policy,
        egress,
    } = fixture;
    drop((egress, policy));
    let field = |event: &dogwood_language::Event, path: &[&str]| {
        event
            .field_path(&path.iter().map(|name| name.to_string()).collect::<Vec<_>>())
            .cloned()
    };
    let text = |value: &str| Some(Value::String(value.to_string()));
    let events = history::events(&history.path().join("dogwood.redb"));
    let seen: Vec<_> = events
        .iter()
        .map(|event| (event.action().to_string(), event.kind().to_string()))
        .collect();
    let expected = [
        ("http:request", "request"),
        ("http:request", "response"),
        ("websocket:send", "request"),
        ("websocket:send", "response"),
        ("websocket:receive", "request"),
        ("websocket:receive", "error"),
    ];
    assert_eq!(
        seen,
        expected.map(|(action, kind)| (action.to_string(), kind.to_string()))
    );
    for handshake in &events[..2] {
        assert_eq!(field(handshake, &["input", "upgrade"]), text("websocket"));
    }
    assert_eq!(
        field(&events[1], &["output", "status"]),
        Some(Value::Int(101))
    );
    let body_bytes = |event| field(event, &["input", "body_bytes"]);
    assert_eq!(body_bytes(&events[2]), Some(Value::Int(53)), "the offer");
    assert_eq!(body_bytes(&events[3]), Some(Value::Int(20)), "the delivery");
    assert_eq!(
        history::identifier(&events[2]),
        history::identifier(&events[3])
    );
    assert_eq!(
        field(&events[5], &["input", "opcode"]),
        Some(Value::Entity {
            ty: "Box::WebSocketOpcode".to_string(),
            id: "close".to_string(),
        })
    );
    assert_eq!(field(&events[5], &["input", "host"]), text(REALTIME));
}
