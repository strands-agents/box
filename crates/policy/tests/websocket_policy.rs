#![cfg(feature = "egress-adapter")]

#[path = "support/history.rs"]
mod history;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dogwood_language::Value;
use egress_gateway::{EffectAttempt, EffectInterceptor, EffectOutcome};
use policy::{
    EgressPolicyInterceptor, FsOperation, FsResult, GovernedBox, Outcome, PathResolver, Policy,
    PolicyEngine, Principal, Request,
};

const SAMPLE: &str = r#"
@id("github_read")
permit (principal, action == Box::Action::"http:request", resource)
when { context.input.host == "api.github.com" && context.input.method == "GET" &&
       context.input.upgrade == "" };
@id("none_after_key")
@description("Nothing leaves after the SSH key is read.")
forbid (principal, action == Box::Action::"http:request", resource)
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
"#;

const GITHUB: &str = "api.github.com";
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

#[test]
fn upgrade_separates_a_handshake_from_an_http_request() {
    let fixture = Fixture::open();
    assert!(fixture.admits(&handshake(GITHUB, "/events", "")));
    assert!(!fixture.admits(&handshake(GITHUB, "/events", "websocket")));
    assert!(fixture.admits(&handshake(REALTIME, "/v1/realtime", "websocket")));
    assert!(!fixture.admits(&handshake(REALTIME, "/v1/realtime", "")));
}

#[test]
fn the_guard_refuses_the_next_handshake() {
    let fixture = Fixture::open();
    fixture.read_the_key();
    assert!(!fixture.admits(&handshake(REALTIME, "/v1/realtime", "websocket")));
    assert!(!fixture.admits(&handshake(GITHUB, "/events", "")));
}

#[test]
fn a_handshake_records_one_http_request_with_its_upgrade_and_status() {
    let fixture = Fixture::open();
    fixture.deliver(
        &handshake(REALTIME, "/v1/realtime", "websocket"),
        EffectOutcome::Replied {
            accepted_bytes: 0,
            status: 101,
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
    let events = history::events(&history.path().join("dogwood.redb"));
    let seen: Vec<_> = events
        .iter()
        .map(|event| (event.action().to_string(), event.kind().to_string()))
        .collect();
    assert_eq!(
        seen,
        [("http:request", "request"), ("http:request", "response")]
            .map(|(action, kind)| (action.to_string(), kind.to_string()))
    );
    for event in &events {
        assert_eq!(
            field(event, &["input", "upgrade"]),
            Some(Value::String("websocket".to_string()))
        );
    }
    assert_eq!(
        field(&events[1], &["output", "status"]),
        Some(Value::Int(101))
    );
    assert_eq!(
        history::identifier(&events[0]),
        history::identifier(&events[1])
    );
}
