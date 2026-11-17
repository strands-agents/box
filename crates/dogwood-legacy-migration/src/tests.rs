use std::os::fd::AsRawFd;
use std::path::PathBuf;

use dogwood_language::{DEFAULT_EVENT_SCHEMA, Event};
use dogwood_local_engine::{Snapshot, Write as LogWrite};

use super::*;

const SCHEMA: &str = r#"
namespace Test {
  entity User;
  entity Doc;
  action "Read" appliesTo { principal: [User], resource: [Doc], context: { input: { host?: String } } };
  action "Export" appliesTo { principal: [User], resource: [Doc], context: { input: { host?: String } } };
}
"#;
const POLICY: &str = r#"
permit (principal, action in [Test::Action::"Read", Test::Action::"Export"], resource);
forbid (principal, action == Test::Action::"Export", resource)
when temporal { formerly within 1h Test::Action::"Read"::request{} };
"#;

fn request(source: &str) -> CompileRequest {
    CompileRequest {
        source: source.to_string(),
        event_schema: DEFAULT_EVENT_SCHEMA.to_string(),
        action_schema: SCHEMA.to_string(),
    }
}

fn scratch() -> (tempfile::NamedTempFile, PathBuf) {
    let file = tempfile::NamedTempFile::new().expect("scratch file");
    let path = PathBuf::from(format!("/dev/fd/{}", file.as_file().as_raw_fd()));
    let mut engine = DurableTemporalEngine::open(&path, 0).expect("new engine");
    engine
        .install(POLICY, SCHEMA, None, None)
        .expect("installed policies");
    engine
        .submit(Event::builder("Test::Action::Read", "request"))
        .expect("recorded event");
    drop(engine);
    (file, path)
}

#[test]
fn compile_returns_exact_old_static_has_spelling_and_policy_order() {
    let source = r#"permit (principal, action == Test::Action::"Read", resource) when { context has input.host };"#;
    let compiled = compile(request(source)).expect("valid compile");
    assert_eq!(compiled.statements, vec![
        "permit (principal, action == Test::Action::\"Read\", resource)\nwhen { context has \"input\".host };".to_string()
    ]);
    let compiled = compile(request(POLICY)).expect("valid temporal compile");
    assert_eq!(compiled.statements.len(), 2);
    assert!(compiled.statements[0].starts_with("permit"));
    assert!(compiled.statements[1].starts_with("forbid"));
}

#[test]
fn compile_rejects_action_accepted_by_parsing_but_unknown_to_schema() {
    let source = r#"permit (principal, action == Test::Action::"Missing", resource);"#;
    let service = ServiceSchema::defaults();
    assert!(ParsedPolicySet::parse(source, &service).is_ok());
    assert!(compile(request(source)).is_err());
}

#[test]
fn compile_rejects_invalid_source_and_empty_event_schema() {
    assert!(compile(request("this is not policy")).is_err());
    let mut invalid = request(POLICY);
    invalid.event_schema.clear();
    assert!(compile(invalid).is_err());
}

#[test]
fn compile_refuses_provider_invocations() {
    let source = r#"permit (principal, action == Test::Action::"Read", resource) when { Acme::lookup("x") };"#;
    assert!(matches!(
        compile(request(source)),
        Err(Error::Refused(
            "legacy migration does not support information providers"
        ))
    ));
}

#[test]
fn protocol_refuses_unknown_fields_trailing_data_and_oversized_input() {
    assert!(
        read_request(
            br#"{"source":"","event_schema":"","action_schema":"","path":"/tmp/a"}"#.as_slice()
        )
        .is_err()
    );
    assert!(
        read_request(br#"{"source":"","event_schema":"","action_schema":""} {}"#.as_slice())
            .is_err()
    );
    assert!(matches!(
        read_request(vec![b' '; MAX_MESSAGE + 1].as_slice()),
        Err(Error::Refused("compile input exceeds 8 MiB"))
    ));
}

#[test]
fn protocol_response_limit_includes_newline() {
    assert_eq!(
        encode_response(&Version::legacy()).expect("version"),
        b"{\"protocol\":1,\"engine_version\":\"1.0.0\",\"language_version\":\"1.0.0\"}\n"
    );
    assert!(encode_response(&"x".repeat(MAX_MESSAGE - 2)).is_err());
}

#[test]
fn arguments_refuse_paths_and_extra_options() {
    assert_eq!(
        Mode::parse([OsString::from("validate")].into_iter()).expect("mode"),
        Mode::Validate
    );
    assert!(
        Mode::parse([OsString::from("checkpoint"), OsString::from("/tmp/store")].into_iter())
            .is_err()
    );
    assert!(Mode::parse([OsString::from("--clock")].into_iter()).is_err());
    assert!(Mode::parse([].into_iter()).is_err());
}

#[test]
fn scratch_input_refuses_empty_files_and_directories() {
    let file = tempfile::NamedTempFile::new().expect("empty");
    assert!(check_file(file.as_file()).is_err());
    let dir = tempfile::tempdir().expect("directory");
    assert!(check_file(&File::open(dir.path()).expect("directory descriptor")).is_err());
}

#[test]
fn checkpoint_and_validation_preserve_policies_timestamps_and_monitor_bytes() {
    let (file, path) = scratch();
    let engine = DurableTemporalEngine::open(&path, 0).expect("recover input");
    let original_policies = engine.list();
    let original_end = engine.log_offset();
    drop(engine);
    let first = database(file.as_file(), &path, Mode::Checkpoint).expect("checkpoint");
    assert_eq!(first.policies, original_policies);
    assert_eq!(first.offset, original_end);
    assert!(first.last_ts > 0);
    let second = database(file.as_file(), &path, Mode::Validate).expect("validate pruned snapshot");
    assert_eq!(
        encode_response(&first).expect("first"),
        encode_response(&second).expect("second")
    );
    let log = DurableLog::open(&path).expect("log");
    assert_eq!(log.base_offset(), original_end);
    assert_eq!(log.next_offset(), original_end);
}

#[test]
fn validation_refuses_full_log_and_snapshot_with_replayable_suffix() {
    let (file, path) = scratch();
    assert!(database(file.as_file(), &path, Mode::Validate).is_err());
    database(file.as_file(), &path, Mode::Checkpoint).expect("checkpoint");
    let mut engine = DurableTemporalEngine::open(&path, 0).expect("recover");
    engine
        .submit(Event::builder("Test::Action::Read", "request"))
        .expect("suffix event");
    drop(engine);
    assert!(database(file.as_file(), &path, Mode::Validate).is_err());
    assert!(database(file.as_file(), &path, Mode::Checkpoint).is_ok());
}

#[test]
fn validation_refuses_corrupt_monitor_bytes_without_full_replay_fallback() {
    let (file, path) = scratch();
    database(file.as_file(), &path, Mode::Checkpoint).expect("checkpoint");
    let log = DurableLog::open(&path).expect("log");
    let end = log.next_offset();
    let mut payload = snapshot_only(&log, end).expect("snapshot");
    payload.engine = b"not an engine snapshot".to_vec();
    log.commit(&[LogWrite::Snapshot(&Snapshot {
        up_to_offset: end,
        payload: payload.encode().expect("encode"),
    })])
    .expect("corrupt fixture");
    drop(log);
    assert!(database(file.as_file(), &path, Mode::Validate).is_err());
}

#[test]
fn validation_uses_production_clock_skew_limit() {
    let (file, path) = scratch();
    database(file.as_file(), &path, Mode::Checkpoint).expect("checkpoint");
    let log = DurableLog::open(&path).expect("log");
    let end = log.next_offset();
    let mut payload = snapshot_only(&log, end).expect("snapshot");
    payload.last_ts = i64::MAX;
    log.commit(&[LogWrite::Snapshot(&Snapshot {
        up_to_offset: end,
        payload: payload.encode().expect("encode"),
    })])
    .expect("future fixture");
    drop(log);
    assert!(database(file.as_file(), &path, Mode::Validate).is_err());
}
