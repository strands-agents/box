use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use strands_box_cli::FakeHost;
use strands_box_cli_telemetry::Event;

use super::*;

fn capture(
    emit: impl Fn(Event) + Send + Sync + 'static,
) -> impl FnOnce(Invocation, LaunchOutcome) -> Option<Session> {
    move |invocation, outcome| Some(Session::start(invocation, outcome, emit))
}

fn captured(
    launcher: &Launcher,
    name: &str,
    workspace: PathBuf,
) -> (Result<(), Error>, Vec<Value>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let recorded = events.clone();
    let result = prepare_run(
        name,
        None,
        launcher,
        Ok(workspace),
        Instant::now() - Duration::from_secs(1),
        |_| panic!("an existing or invalid profile does not need creation"),
        capture(move |event| {
            recorded
                .lock()
                .unwrap()
                .push(serde_json::to_value(event).unwrap())
        }),
    )
    .map(|_| ());
    let events = events.lock().unwrap().clone();
    (result, events)
}

fn assert_failure(events: &[Value], reason: &str) {
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0]["event"], "run/1");
    assert_eq!(
        events[0]["data"],
        json!({"box_launched": false, "failure_reason": reason, "startup_latency_ms": null})
    );
    assert_eq!(events[1]["event"], "shutdown/1");
    assert_eq!(events[1]["data"]["exit_outcome"], "nonzero");
    assert_eq!(events[1]["data"].get("core_outcome"), Some(&Value::Null));
    assert!(
        events[1]["data"]["invocation_duration_ms"]
            .as_u64()
            .unwrap()
            >= 1000
    );
    for field in ["v", "installation_id", "run_id", "context"] {
        assert_eq!(events[0][field], events[1][field], "{field}");
    }
}

#[test]
fn failures_before_preparation_emit_run_and_shutdown() {
    let host = FakeHost::new();
    let launcher = host.launcher();
    let (result, events) = captured(&launcher, "bad name", host.project());
    assert!(matches!(result, Err(Error::ProfileName { .. })));
    assert_failure(&events, "profile_invalid");
    assert_eq!(events[0]["context"]["profile_hash"], Value::Null);
    let installation = std::fs::read_to_string(
        launcher
            .profiles()
            .root()
            .parent()
            .unwrap()
            .join("installation.toml"),
    )
    .unwrap();
    let installation: toml::Value = toml::from_str(&installation).unwrap();
    assert_eq!(
        events[0]["installation_id"],
        installation["installation_id"].as_str().unwrap()
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn preparation_failure_keeps_the_loaded_profile_context() {
    let host = FakeHost::new();
    let launcher = host.launcher();
    let folder = launcher.profiles().root().join("invalid");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("profile.toml"), "[").unwrap();
    let (result, events) = captured(&launcher, "invalid", host.project());
    assert!(matches!(result, Err(Error::Profile { .. })));
    assert_failure(&events, "profile_invalid");
    assert_eq!(
        events[0]["context"]["profile_hash"],
        "245843abef9e72e7efac30138a994bf6301e7e1d7d7042a33d42e863d2638811"
    );
    assert_eq!(events[0]["context"]["profile_policy_present"], Value::Null);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_profile_path_failure_names_its_category() {
    let host = FakeHost::new();
    let launcher = host.launcher();
    let missing = host.home().join("repo/box/profile.toml");
    let (result, events) = captured(&launcher, &missing.display().to_string(), host.project());
    assert!(matches!(result, Err(Error::ProfilePath { .. })));
    assert_failure(&events, "profile_missing");

    std::fs::create_dir_all(missing.parent().unwrap()).unwrap();
    std::fs::write(&missing, "[agent]\ncommand = [\"/usr/bin/true\"]\n").unwrap();
    let (result, events) = captured(&launcher, &missing.display().to_string(), host.project());
    assert!(matches!(result, Err(Error::ProfileFileUnnamed { .. })));
    assert_failure(&events, "profile_invalid");
}

#[test]
fn unavailable_identity_preserves_the_failure_without_events() {
    let host = FakeHost::new();
    let launcher = host.launcher();
    std::fs::create_dir_all(
        launcher
            .profiles()
            .root()
            .parent()
            .unwrap()
            .join("installation.toml"),
    )
    .unwrap();
    let (result, events) = captured(&launcher, "bad name", host.project());
    assert!(matches!(result, Err(Error::ProfileName { .. })));
    assert!(events.is_empty());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn startup_excludes_profile_creation_and_shutdown_keeps_the_full_invocation() {
    for existing_profile in [false, true] {
        startup_after_profile_setup(existing_profile);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn startup_after_profile_setup(existing_profile: bool) {
    let host = FakeHost::new();
    let launcher = host.launcher();
    let folder = launcher.profiles().root().join("claude");
    let write_profile = || {
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(
            folder.join("profile.toml"),
            "[agent]\ncommand = [\"/usr/bin/true\"]\n",
        )
        .unwrap();
    };
    if existing_profile {
        write_profile();
    }
    let started = Instant::now() - Duration::from_secs(1);
    let mut setup_completed_at = SystemTime::now();
    let mut created = false;
    let events = Arc::new(Mutex::new(Vec::new()));
    let recorded = events.clone();
    let (launch, session) = prepare_run(
        "claude",
        None,
        &launcher,
        Ok(host.project()),
        started,
        |name| {
            assert_eq!(name, "claude");
            assert!(!existing_profile);
            write_profile();
            std::thread::sleep(Duration::from_millis(150));
            setup_completed_at = SystemTime::now();
            created = true;
            Ok(())
        },
        capture(move |event| {
            recorded
                .lock()
                .unwrap()
                .push(serde_json::to_value(event).unwrap());
        }),
    )
    .unwrap();
    assert_eq!(created, !existing_profile);
    assert!(events.lock().unwrap().is_empty());
    let mut session = session.unwrap();
    let source_timestamp = observe_startup(&launch, &mut session);
    let completed = Instant::now();
    session.finish(completed, ExitOutcome::Zero);
    let events = events.lock().unwrap();
    assert_eq!(events.len(), 3, "{events:?}");
    assert_eq!(events[0]["event"], "run/1");
    assert_eq!(events[0]["data"]["box_launched"], true);
    assert_eq!(events[0]["data"]["failure_reason"], Value::Null);
    let latency = events[0]["data"]["startup_latency_ms"].as_u64().unwrap();
    let after_setup_ms = source_timestamp
        .duration_since(setup_completed_at)
        .unwrap()
        .as_millis() as u64;
    assert!(latency >= 125, "{latency}");
    assert!(latency <= after_setup_ms, "{latency} > {after_setup_ms}");
    assert_eq!(events[1]["event"], "polling/1");
    assert_eq!(events[1]["data"]["decisions"], json!([]));
    assert_eq!(events[2]["event"], "shutdown/1");
    assert_eq!(events[2]["data"].get("core_outcome"), Some(&Value::Null));
    assert_eq!(
        events[2]["data"]["invocation_duration_ms"],
        completed.duration_since(started).as_millis() as u64
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn startup_includes_launch_preparation() {
    let host = FakeHost::new();
    let launcher = host.launcher();
    let folder = launcher.profiles().root().join("prepared");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(
        folder.join("profile.toml"),
        "[agent]\ncommand = [\"/usr/bin/true\"]\n",
    )
    .unwrap();
    let mut preparation_entered_at = SystemTime::UNIX_EPOCH;
    let events = Arc::new(Mutex::new(Vec::new()));
    let recorded = events.clone();
    let (launch, session) = capture_preparation(
        || {
            preparation_entered_at = SystemTime::now();
            std::thread::sleep(Duration::from_millis(150));
            launcher.prepare_with_context("prepared", &host.project(), None)
        },
        Instant::now(),
        capture(move |event| {
            recorded
                .lock()
                .unwrap()
                .push(serde_json::to_value(event).unwrap());
        }),
    )
    .unwrap();
    let mut session = session.unwrap();
    let source_timestamp = observe_startup(&launch, &mut session);
    session.finish(Instant::now(), ExitOutcome::Zero);
    let events = events.lock().unwrap();
    let latency = events[0]["data"]["startup_latency_ms"].as_u64().unwrap();
    let preparation_ms = source_timestamp
        .duration_since(preparation_entered_at)
        .unwrap()
        .as_millis() as u64;
    assert!(latency >= preparation_ms, "{latency} < {preparation_ms}");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn observe_startup(launch: &Launch, session: &mut Session) -> SystemTime {
    session.observe(
        strands_box_cli_telemetry::Journal::start(launch.journal()).unwrap(),
        strands_box_cli_telemetry::ActionCatalog::new([]),
    );
    let source_timestamp = SystemTime::now() + Duration::from_millis(125);
    let timestamp = source_timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_string();
    std::fs::write(
        launch.journal(),
        format!(
            "{}\n",
            json!({"resourceLogs":[{
                "resource":{"attributes":[
                    {"key":"service.name","value":{"stringValue":"strands-box"}},
                    {"key":"strands.box.source","value":{"stringValue":"box"}}
                ]},
                "scopeLogs":[{"scope":{"name":"strands-box.control"},"logRecords":[{
                    "timeUnixNano":timestamp,
                    "attributes":[
                        {"key":"strands.box.control.operation","value":{"stringValue":"workload_started"}},
                        {"key":"strands.box.control.outcome","value":{"stringValue":"ok"}}
                    ]
                }]}]
            }]})
        ),
    )
    .unwrap();
    source_timestamp
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn profile_creation_failure_preserves_its_error_and_emits_null_latency() {
    let host = FakeHost::new();
    let launcher = host.launcher();
    let events = Arc::new(Mutex::new(Vec::new()));
    let recorded = events.clone();
    let result = prepare_run(
        "claude",
        None,
        &launcher,
        Ok(host.project()),
        Instant::now() - Duration::from_secs(1),
        |name| {
            assert_eq!(name, "claude");
            Err(Error::OptionSyntax {
                option: "unanswered".to_string(),
            })
        },
        capture(move |event| {
            recorded
                .lock()
                .unwrap()
                .push(serde_json::to_value(event).unwrap());
        }),
    );
    assert!(matches!(
        result,
        Err(Error::OptionSyntax { option }) if option == "unanswered"
    ));
    assert_failure(&events.lock().unwrap(), "unknown");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_home_workspace_is_refused_before_the_starter_asks_anything() {
    let host = FakeHost::new();
    let launcher = host.launcher();
    assert!(launcher.is_starter("claude").unwrap());
    let above = host.home().parent().unwrap().to_path_buf();
    for workspace in [host.home(), above] {
        let result = prepare_run(
            "claude",
            None,
            &launcher,
            Ok(workspace.clone()),
            Instant::now(),
            |_| panic!("no setup guide for {}", workspace.display()),
            |_, _| None,
        );
        assert!(
            matches!(result, Err(Error::ProjectHoldsHome { .. })),
            "{:?}",
            result.err()
        );
    }
    assert!(!launcher.profiles().contains("claude").unwrap());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_home_workspace_is_refused_before_the_agent_is_checked() {
    let host = FakeHost::new();
    let launcher = host.launcher();
    let folder = launcher.profiles().root().join("searching");
    std::fs::create_dir_all(&folder).unwrap();
    let pack = host.home().join(".strands/box/packs/searching/pack.toml");
    std::fs::create_dir_all(pack.parent().unwrap()).unwrap();
    std::fs::write(
        &pack,
        "[pack]\nname = \"searching\"\nversion = 1\nkind = \"agent\"\n\
         [inputs.agent.path]\ntype = \"program\"\nprogram = \"agent\"\n\
         search = [\"${{ home }}/bin\"]\n[run]\ncommand = [\"${{ inputs.agent.path }}\"]\n",
    )
    .unwrap();
    std::fs::write(folder.join("profile.toml"), "packs = [\"searching\"]\n").unwrap();
    let bin = host.home().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::copy("/usr/bin/true", bin.join("agent")).unwrap();
    let error = launcher
        .preview("searching", &host.home())
        .expect_err("a refusal from box profile show");
    assert!(matches!(error, Error::ProjectHoldsHome { .. }), "{error}");
    let error = launcher
        .prepare("searching", &host.home(), None)
        .expect_err("a refusal");
    assert!(matches!(error, Error::ProjectHoldsHome { .. }), "{error}");
    let message = error.to_string();
    assert!(message.contains("is your home folder"), "{message}");
    assert!(message.contains("cd into a project folder"), "{message}");
}

#[test]
fn the_last_banner_flag_wins_and_no_flag_leaves_the_choice_to_the_files() {
    for (args, expected) in [
        (&[][..], None),
        (&["--banner"][..], Some(true)),
        (&["--no-banner"][..], Some(false)),
        (&["--banner", "--no-banner"][..], Some(false)),
        (&["--no-banner", "--banner"][..], Some(true)),
    ] {
        let parsed = Cli::try_parse_from(["box", "run", "claude"].iter().chain(args))
            .expect("the flags parse");
        let Command::Run {
            banner, no_banner, ..
        } = parsed.command
        else {
            panic!("a run");
        };
        assert_eq!(flag(banner, no_banner), expected, "{args:?}");
    }
}

#[test]
fn box_run_hands_the_flag_choice_to_its_launcher() {
    for banner in [None, Some(true), Some(false)] {
        assert_eq!(run_launcher(banner).banner_flag(), banner);
    }
}
