use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use serde_json::{Value, json};
use strands_box_cli_telemetry::{Invocation, LaunchOutcome};

use super::*;

#[test]
fn launch_observation_preserves_results_and_finishes_under_the_instance_lock() {
    for (evidence, core_outcome, identity_available, scenario) in [
        (None, None, true, 0),
        (Some(false), None, true, 1),
        (Some(true), None, true, 2),
        (Some(true), Some("ok"), true, 0),
        (Some(true), Some("ok"), true, 1),
        (Some(true), Some("refused"), true, 2),
        (Some(false), Some("refused"), true, 1),
        (Some(true), Some("ok"), false, 0),
        (Some(false), None, false, 1),
        (None, None, false, 2),
    ] {
        let observed = evidence == Some(true);
        let host = crate::FakeHost::new();
        let launcher = host.launcher().box_home(host.home().join("box-data"));
        let folder = launcher.profiles().root().join("observed");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(
            folder.join("profile.toml"),
            "[agent]\ncommand = [\"/usr/bin/true\"]\n",
        )
        .unwrap();
        if !identity_available {
            std::fs::create_dir_all(host.home().join(".strands/box/installation.toml")).unwrap();
        }
        let started = Instant::now() - Duration::from_secs(1);
        let started_at = SystemTime::now() - Duration::from_secs(1);
        let prepared = launcher.prepare_with_context("observed", &host.project(), None);
        let launch = prepared.result.unwrap();
        if evidence.is_none() {
            std::fs::create_dir(launch.journal()).unwrap();
        }
        let directory = launch.config().parent().unwrap().to_path_buf();
        let locked = directory.clone();
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = events.clone();
        assert_eq!(prepared.installation_id.is_some(), identity_available);
        let session = prepared.installation_id.map(|installation_id| {
            let invocation =
                Invocation::new(installation_id, prepared.context, started, started_at).unwrap();
            Session::start(invocation, LaunchOutcome::Unknown, move |event| {
                let claim = std::fs::File::open(&locked).unwrap();
                assert!(matches!(
                    claim.try_lock(),
                    Err(std::fs::TryLockError::WouldBlock)
                ));
                captured
                    .lock()
                    .unwrap()
                    .push(serde_json::to_value(event).unwrap());
            })
        });
        let mut completion_floor_ms = 0_u64;
        let result = launch.run_observed(session, |launch| {
            assert!(events.lock().unwrap().is_empty());
            let mut records = Vec::new();
            if observed {
                let timestamp = (started_at + Duration::from_micros(125_750))
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
                    .to_string();
                records.push(json!({
                    "timeUnixNano":timestamp,
                    "attributes":[
                        {"key":"strands.box.control.operation","value":{"stringValue":"box_started"}},
                        {"key":"strands.box.control.outcome","value":{"stringValue":"ok"}}
                    ]
                }));
            }
            let before = started.elapsed().as_millis();
            std::thread::sleep(Duration::from_millis(3));
            completion_floor_ms = started.elapsed().as_millis().try_into().unwrap();
            assert!(u128::from(completion_floor_ms) > before);
            if let Some(outcome) = core_outcome {
                records.push(json!({
                    "attributes":[
                        {"key":"strands.box.control.operation","value":{"stringValue":"box_stopped"}},
                        {"key":"strands.box.control.outcome","value":{"stringValue":outcome}}
                    ]
                }));
            }
            if !records.is_empty() {
                let mut journal = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(launch.journal())
                    .unwrap();
                writeln!(
                    journal,
                    "{}",
                    json!({"resourceLogs":[{
                        "resource":{"attributes":[
                            {"key":"service.name","value":{"stringValue":"strands-box"}},
                            {"key":"strands.box.source","value":{"stringValue":"box"}}
                        ]},
                        "scopeLogs":[{
                            "scope":{"name":"strands-box.control"},
                            "logRecords":records
                        }]
                    }]})
                ).unwrap();
            }
            match scenario {
                0 => Ok(ExitCode::SUCCESS),
                1 => Ok(ExitCode::from(7)),
                _ => Err(Error::NoHome),
            }
        });
        assert!(
            completion_floor_ms >= 1000,
            "execution runs even without telemetry"
        );
        match scenario {
            0 => assert_eq!(result.unwrap(), ExitCode::SUCCESS),
            1 => assert_eq!(result.unwrap(), ExitCode::from(7)),
            _ => assert!(matches!(result, Err(Error::NoHome))),
        }
        let events = events.lock().unwrap();
        std::fs::File::open(directory).unwrap().try_lock().unwrap();
        assert!(!host.home().join("box-data/installation.toml").exists());
        if !identity_available {
            assert!(events.is_empty());
            continue;
        }
        let polled = observed || core_outcome.is_some();
        assert_eq!(events.len(), if polled { 3 } else { 2 }, "{events:?}");
        assert_eq!(events[0]["event"], "run/1");
        assert_eq!(
            events[0]["data"],
            json!({
                "box_launched": observed.then_some(true),
                "failure_reason":null,
                "startup_latency_ms":observed.then_some(125)
            })
        );
        if polled {
            assert_eq!(events[1]["event"], "polling/1");
            assert_eq!(events[1]["data"]["decisions"], json!([]));
        }
        let shutdown = events.last().unwrap();
        assert_eq!(shutdown["event"], "shutdown/1");
        assert_eq!(
            shutdown["data"].get("core_outcome"),
            Some(&json!(core_outcome))
        );
        assert_eq!(
            shutdown["data"]["exit_outcome"],
            if scenario == 0 { "zero" } else { "nonzero" }
        );
        for field in ["v", "installation_id", "run_id", "context"] {
            for event in &events[1..] {
                assert_eq!(events[0][field], event[field], "{field}");
            }
        }
        assert!(
            shutdown["data"]["invocation_duration_ms"].as_u64().unwrap() >= completion_floor_ms,
            "invocation duration includes the completed execution"
        );
    }
}

#[test]
fn polling_counts_only_decisions_written_during_the_run() {
    use std::io::Write;

    let host = crate::FakeHost::new();
    let launcher = host.launcher().box_home(host.home().join("box-data"));
    let folder = launcher.profiles().root().join("polling");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(
        folder.join("profile.toml"),
        "[agent]\ncommand = [\"/usr/bin/true\"]\n\
         [mcp.fs]\ntype = \"stdio\"\ncommand = [\"true\"]\n\
         env.PATH = \"/usr/bin:/bin\"\n",
    )
    .unwrap();
    let prepared = launcher.prepare_with_context("polling", &host.project(), None);
    let launch = prepared.result.unwrap();
    let decision = json!({"resourceLogs":[{
        "resource":{"attributes":[
            {"key":"service.name","value":{"stringValue":"strands-box"}},
            {"key":"strands.box.source","value":{"stringValue":"box"}}
        ]},
        "scopeLogs":[{"scope":{"name":"strands-box.policy"},"logRecords":[{
            "eventName":"strands.box.policy.decision",
            "attributes":[
                {"key":"strands.box.policy.action","value":{"stringValue":"fs:read"}},
                {"key":"strands.box.policy.category","value":{"stringValue":"fs"}},
                {"key":"strands.box.policy.verdict","value":{"stringValue":"permit"}}
            ]
        }]}]
    }]});
    std::fs::write(launch.journal(), format!("{decision}\n{decision}\n")).unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = events.clone();
    let session = Session::start(
        Invocation::new(
            prepared.installation_id.unwrap(),
            prepared.context,
            Instant::now(),
            SystemTime::now(),
        )
        .unwrap(),
        LaunchOutcome::Unknown,
        move |event| {
            captured
                .lock()
                .unwrap()
                .push(serde_json::to_value(event).unwrap())
        },
    );
    launch
        .run_observed(Some(session), |launch| {
            let mut journal = std::fs::OpenOptions::new()
                .append(true)
                .open(launch.journal())
                .unwrap();
            writeln!(journal, "{decision}").unwrap();
            Ok(ExitCode::SUCCESS)
        })
        .unwrap();
    let events: std::sync::MutexGuard<'_, Vec<Value>> = events.lock().unwrap();
    assert_eq!(events.len(), 3, "{events:?}");
    assert_eq!(events[0]["event"], "run/1");
    assert_eq!(events[1]["event"], "polling/1");
    assert_eq!(
        events[1]["data"]["decisions"],
        json!([{
            "action":"unknown", "outcome":"permitted", "count":1
        }])
    );
    assert_eq!(events[2]["event"], "shutdown/1");
}

#[test]
fn an_early_failure_keeps_identity_in_the_default_box_home() {
    let host = crate::FakeHost::new();
    let selected = host.home().join("box-data");
    let launcher = host.launcher().box_home(&selected);
    let prepared = launcher.failed_preparation(Error::UnsupportedPlatform);
    assert!(matches!(prepared.result, Err(Error::UnsupportedPlatform)));
    let installation: toml::Table =
        std::fs::read_to_string(host.home().join(".strands/box/installation.toml"))
            .unwrap()
            .parse()
            .unwrap();
    assert_eq!(
        serde_json::to_value(prepared.installation_id.unwrap()).unwrap(),
        installation["installation_id"].as_str().unwrap()
    );
    assert!(!selected.join("installation.toml").exists());
    assert_eq!(
        serde_json::to_value(prepared.context).unwrap()["profile_hash"],
        Value::Null
    );
}

fn shared_launch(host: &crate::FakeHost) -> Launch {
    let launcher = host.launcher().box_home(host.home().join("box-data"));
    let folder = launcher.profiles().root().join("shared");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(
        folder.join("profile.toml"),
        "[agent]\ncommand = [\"/usr/bin/true\"]\n",
    )
    .unwrap();
    launcher
        .prepare_with_context("shared", &host.project(), None)
        .result
        .unwrap()
}

fn run_is_locked(directory: &Path) -> bool {
    matches!(
        std::fs::File::open(directory).unwrap().try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    )
}

#[test]
fn a_dropped_launch_unlocks_its_run_while_a_forked_child_shares_the_file() {
    let host = crate::FakeHost::new();
    let launch = shared_launch(&host);
    let directory = launch.config().parent().unwrap().to_path_buf();
    let journal = launch._claim.clone();
    let child = launch._claim.0.try_clone().unwrap();

    drop(journal);
    drop(launch);
    assert!(!run_is_locked(&directory));
    drop(child);
}

#[test]
fn a_dropped_launch_keeps_its_run_locked_while_the_journal_holds_the_claim() {
    let host = crate::FakeHost::new();
    let launch = shared_launch(&host);
    let directory = launch.config().parent().unwrap().to_path_buf();
    let journal = launch._claim.clone();
    let child = launch._claim.0.try_clone().unwrap();

    drop(launch);
    assert!(run_is_locked(&directory));
    drop(journal);
    assert!(!run_is_locked(&directory));
    drop(child);
}
