use std::time::{Duration, Instant, SystemTime};

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use uuid::Uuid;

use crate::{InstallationId, Polling, RunContext};

pub(crate) const MAX_INTEGER: u64 = 9_007_199_254_740_991;

/// The IDs, context, and timing origins of one CLI invocation.
pub struct Invocation {
    installation_id: InstallationId,
    run_id: Uuid,
    context: RunContext,
    pub(crate) started: Instant,
    startup_started_at: SystemTime,
}

/// One complete service event.
#[derive(Debug, Clone)]
pub struct Event {
    v: u8,
    installation_id: InstallationId,
    run_id: Uuid,
    context: RunContext,
    message: Message,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
enum Message {
    Run(RunData),
    Shutdown(ShutdownData),
    Polling(Polling),
}

impl Serialize for Event {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let name = match &self.message {
            Message::Run(_) => "run/1",
            Message::Shutdown(_) => "shutdown/1",
            Message::Polling(_) => "polling/1",
        };
        let mut event = serializer.serialize_struct("Event", 6)?;
        event.serialize_field("v", &self.v)?;
        event.serialize_field("event", name)?;
        event.serialize_field("installation_id", &self.installation_id)?;
        event.serialize_field("run_id", &self.run_id)?;
        event.serialize_field("context", &self.context)?;
        event.serialize_field("data", &self.message)?;
        event.end()
    }
}

#[derive(Debug, Clone, Serialize)]
struct ShutdownData {
    invocation_duration_ms: u64,
    exit_outcome: ExitOutcome,
    core_outcome: Option<CoreOutcome>,
    core_failure_code: Option<&'static str>,
}

/// The process result on controlled completion.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitOutcome {
    Zero,
    Nonzero,
}

/// The outcome reported by this invocation's Core stop record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreOutcome {
    Ok,
    Refused,
}

#[derive(Debug, Clone, Serialize)]
struct RunData {
    box_launched: Option<bool>,
    failure_reason: Option<FailureReason>,
    startup_latency_ms: Option<u64>,
}

/// A preparation failure category, without diagnostic text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    ProfileMissing,
    ProfileInvalid,
    AgentNotFound,
    PolicyRejected,
    Unknown,
}

/// The evidence available when a run event is constructed.
#[derive(Debug, Clone, Copy)]
pub enum LaunchOutcome {
    Confirmed(Option<SystemTime>),
    NotLaunched,
    Unknown,
    PreparationFailed(FailureReason),
}

impl Invocation {
    /// An invocation with command-entry and launch-preparation clock origins.
    pub fn new(
        installation_id: InstallationId,
        context: RunContext,
        started: Instant,
        startup_started_at: SystemTime,
    ) -> Option<Self> {
        Some(Self {
            installation_id,
            run_id: random_run_id(getrandom::fill)?,
            context,
            started,
            startup_started_at,
        })
    }

    /// The monotonic instant at which this invocation began.
    pub fn started(&self) -> Instant {
        self.started
    }

    /// The `User-Agent` for delivery: `box/` and the version the events report in their context.
    pub(crate) fn user_agent(&self) -> String {
        format!("box/{}", self.context.box_version)
    }

    /// Construct the run event from an observed outcome.
    pub fn run_event(&self, outcome: LaunchOutcome) -> Event {
        let (box_launched, failure_reason, startup_latency_ms) = match outcome {
            LaunchOutcome::Confirmed(source_timestamp) => (
                Some(true),
                None,
                source_timestamp
                    .and_then(|timestamp| timestamp.duration_since(self.startup_started_at).ok())
                    .map(elapsed_ms),
            ),
            LaunchOutcome::NotLaunched => (Some(false), None, None),
            LaunchOutcome::Unknown => (None, None, None),
            LaunchOutcome::PreparationFailed(reason) => (Some(false), Some(reason), None),
        };
        self.event(Message::Run(RunData {
            box_launched,
            failure_reason,
            startup_latency_ms,
        }))
    }

    /// Construct the completion event at the supplied monotonic instant. `core_failure_code` is the
    /// message code of the failure that ended Core's run, such as `B0114`, or `uncoded`.
    pub fn shutdown_event(
        &self,
        completed: Instant,
        outcome: ExitOutcome,
        core_outcome: Option<CoreOutcome>,
        core_failure_code: Option<&'static str>,
    ) -> Event {
        self.event(Message::Shutdown(ShutdownData {
            invocation_duration_ms: elapsed_ms(completed.saturating_duration_since(self.started)),
            exit_outcome: outcome,
            core_outcome,
            core_failure_code,
        }))
    }

    /// Construct a polling event from one complete interval's deltas.
    pub fn polling_event(&self, polling: Polling) -> Event {
        self.event(Message::Polling(polling))
    }

    fn event(&self, message: Message) -> Event {
        Event {
            v: 1,
            installation_id: self.installation_id,
            run_id: self.run_id,
            context: self.context.clone(),
            message,
        }
    }
}

fn random_run_id(fill: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>) -> Option<Uuid> {
    let mut bytes = [0; 16];
    fill(&mut bytes).ok()?;
    Some(uuid::Builder::from_random_bytes(bytes).into_uuid())
}

pub(crate) fn elapsed_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(MAX_INTEGER)) as u64
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::ContextBuilder;

    fn invocation() -> Invocation {
        let directory = tempfile::tempdir().unwrap();
        Invocation::new(
            InstallationId::load_or_create(directory.path()).unwrap(),
            ContextBuilder::new("1.2.3").unwrap().finish(),
            Instant::now(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        )
        .unwrap()
    }

    #[test]
    fn run_identity_is_unavailable_when_the_random_source_fails() {
        assert!(random_run_id(|_| Err(getrandom::Error::UNSUPPORTED)).is_none());
        let id = random_run_id(|bytes| {
            bytes.fill(0x55);
            Ok(())
        })
        .unwrap();
        assert_eq!(id.get_version(), Some(uuid::Version::Random));
        assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
    }

    fn validate(event: &Event) -> Value {
        let value = serde_json::to_value(event).unwrap();
        let schema: Value =
            serde_json::from_str(include_str!("../tests/fixtures/box.schema.json")).unwrap();
        jsonschema::validator_for(&schema)
            .unwrap()
            .validate(&value)
            .unwrap();
        value
    }

    #[test]
    fn run_events_match_the_schema_for_every_launch_observation() {
        let invocation = invocation();
        for (outcome, launched, failure) in [
            (LaunchOutcome::Confirmed(None), json!(true), Value::Null),
            (LaunchOutcome::NotLaunched, json!(false), Value::Null),
            (LaunchOutcome::Unknown, Value::Null, Value::Null),
            (
                LaunchOutcome::PreparationFailed(FailureReason::ProfileMissing),
                json!(false),
                json!("profile_missing"),
            ),
        ] {
            let value = validate(&invocation.run_event(outcome));
            assert_eq!(value["event"], "run/1");
            assert_eq!(
                value["data"],
                json!({
                    "box_launched": launched,
                    "failure_reason": failure,
                    "startup_latency_ms": null,
                })
            );
            assert!(value["context"]["profile_hash"].is_null());
            assert_eq!(value.as_object().unwrap().len(), 6);
        }
    }

    #[test]
    fn every_preparation_failure_is_bounded_and_establishes_no_launch() {
        let invocation = invocation();
        for (failure, expected) in [
            (FailureReason::ProfileMissing, "profile_missing"),
            (FailureReason::ProfileInvalid, "profile_invalid"),
            (FailureReason::AgentNotFound, "agent_not_found"),
            (FailureReason::PolicyRejected, "policy_rejected"),
            (FailureReason::Unknown, "unknown"),
        ] {
            let value = validate(&invocation.run_event(LaunchOutcome::PreparationFailed(failure)));
            assert_eq!(value["data"]["box_launched"], false);
            assert_eq!(value["data"]["failure_reason"], expected);
            assert_eq!(value["data"].get("startup_latency_ms"), Some(&Value::Null));
        }
    }

    #[test]
    fn startup_latency_uses_the_source_timestamp_and_floors_milliseconds() {
        let mut invocation = invocation();
        invocation.started = Instant::now() - Duration::from_secs(60);
        let source_timestamp = invocation.startup_started_at + Duration::from_micros(1_234_999);
        let value =
            validate(&invocation.run_event(LaunchOutcome::Confirmed(Some(source_timestamp))));
        assert_eq!(
            value["data"],
            json!({
                "box_launched": true,
                "failure_reason": null,
                "startup_latency_ms": 1234,
            })
        );
    }

    #[test]
    fn confirmed_launch_keeps_null_latency_without_a_usable_source_timestamp() {
        let invocation = invocation();
        for source_timestamp in [
            None,
            Some(invocation.startup_started_at - Duration::from_nanos(1)),
        ] {
            let value = validate(&invocation.run_event(LaunchOutcome::Confirmed(source_timestamp)));
            assert_eq!(
                value["data"],
                json!({
                    "box_launched": true,
                    "failure_reason": null,
                    "startup_latency_ms": null,
                })
            );
        }
    }

    #[test]
    fn startup_latency_preserves_zero_and_saturates_at_the_schema_limit() {
        let invocation = invocation();
        for (duration, expected) in [
            (Duration::ZERO, 0),
            (Duration::from_micros(999), 0),
            (Duration::from_millis(MAX_INTEGER + 1), MAX_INTEGER),
        ] {
            let source_timestamp = invocation.startup_started_at + duration;
            let value =
                validate(&invocation.run_event(LaunchOutcome::Confirmed(Some(source_timestamp))));
            assert_eq!(value["data"]["startup_latency_ms"], expected);
        }
    }

    #[test]
    fn events_keep_context_and_ids_while_each_invocation_gets_a_fresh_id() {
        let directory = tempfile::tempdir().unwrap();
        let installation_id = InstallationId::load_or_create(directory.path()).unwrap();
        let mut context = ContextBuilder::new("1.2.3").unwrap();
        context.profile(b"policies = []\n");
        let context = context.finish();
        let started = Instant::now() - std::time::Duration::from_secs(1);
        let startup_started_at = SystemTime::now();
        let make = || {
            Invocation::new(
                installation_id,
                context.clone(),
                started,
                startup_started_at,
            )
            .unwrap()
        };
        let first = make();
        assert_eq!(first.started(), started);
        let a = validate(&first.run_event(LaunchOutcome::Unknown));
        let b = validate(&first.run_event(LaunchOutcome::Unknown));
        let c = validate(&make().run_event(LaunchOutcome::Unknown));
        assert_eq!(a, b);
        assert_eq!(a["context"], serde_json::to_value(context).unwrap());
        assert_eq!(
            a["installation_id"],
            serde_json::to_value(installation_id).unwrap()
        );
        assert_eq!(a["installation_id"], c["installation_id"]);
        assert_ne!(a["run_id"], c["run_id"]);
    }

    #[test]
    fn shutdown_uses_the_completion_time_and_keeps_the_invocation_envelope() {
        let directory = tempfile::tempdir().unwrap();
        let mut context = ContextBuilder::new("1.2.3").unwrap();
        context.profile(b"policies = [\"policy.dw\"]\n");
        let invocation = Invocation::new(
            InstallationId::load_or_create(directory.path()).unwrap(),
            context.finish(),
            Instant::now(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        )
        .unwrap();
        let run = validate(&invocation.run_event(LaunchOutcome::Unknown));
        let completed = invocation.started() + Duration::from_micros(1_234_999);
        for (outcome, expected) in [
            (ExitOutcome::Zero, "zero"),
            (ExitOutcome::Nonzero, "nonzero"),
        ] {
            for (core_outcome, expected_core) in [
                (None, Value::Null),
                (Some(CoreOutcome::Ok), json!("ok")),
                (Some(CoreOutcome::Refused), json!("refused")),
            ] {
                let shutdown =
                    validate(&invocation.shutdown_event(completed, outcome, core_outcome, None));
                assert_eq!(shutdown["event"], "shutdown/1");
                assert_eq!(
                    shutdown["data"],
                    json!({
                        "invocation_duration_ms": 1234,
                        "exit_outcome": expected,
                        "core_outcome": expected_core,
                        "core_failure_code": null,
                    })
                );
                for key in ["v", "installation_id", "run_id", "context"] {
                    assert_eq!(shutdown[key], run[key], "{key}");
                }
            }
        }
        let early = validate(&invocation.shutdown_event(
            invocation.started() - Duration::from_secs(1),
            ExitOutcome::Nonzero,
            None,
            None,
        ));
        assert_eq!(early["data"]["invocation_duration_ms"], 0);
        // A released CLI sends no `core_failure_code`; the schema must still accept its shutdown event.
        let mut released = refused_without_code(&invocation, completed);
        released["data"]
            .as_object_mut()
            .unwrap()
            .remove("core_failure_code");
        let schema: Value =
            serde_json::from_str(include_str!("../tests/fixtures/box.schema.json")).unwrap();
        assert!(
            jsonschema::validator_for(&schema)
                .unwrap()
                .is_valid(&released)
        );
        for code in ["B0114", "P0303", "uncoded"] {
            let refused = validate(&invocation.shutdown_event(
                completed,
                ExitOutcome::Nonzero,
                None,
                Some(code),
            ));
            assert_eq!(refused["data"]["core_failure_code"], code);
        }
    }

    fn refused_without_code(invocation: &Invocation, completed: Instant) -> Value {
        validate(&invocation.shutdown_event(completed, ExitOutcome::Nonzero, None, None))
    }

    #[test]
    fn durations_floor_milliseconds_and_saturate_at_the_schema_limit() {
        assert_eq!(elapsed_ms(Duration::ZERO), 0);
        assert_eq!(elapsed_ms(Duration::from_micros(999)), 0);
        assert_eq!(elapsed_ms(Duration::from_micros(1999)), 1);
        assert_eq!(
            elapsed_ms(Duration::from_millis(9_007_199_254_740_991)),
            9_007_199_254_740_991
        );
        assert_eq!(
            elapsed_ms(Duration::from_secs(u64::MAX)),
            9_007_199_254_740_991
        );
    }

    #[test]
    fn polling_supports_every_pair_and_preserves_the_invocation_envelope() {
        use crate::{ActionCatalog, Decision, DecisionInterval, Verdict};

        let directory = tempfile::tempdir().unwrap();
        let mut context = ContextBuilder::new("1.2.3").unwrap();
        context.profile(b"policies = [\"policy.dw\"]\n");
        let invocation = Invocation::new(
            InstallationId::load_or_create(directory.path()).unwrap(),
            context.finish(),
            Instant::now(),
            SystemTime::now(),
        )
        .unwrap();
        let actions = [
            ("fs:read", "fs"),
            ("fs:write", "fs"),
            ("fs:delete", "fs"),
            ("fs:move", "fs"),
            ("fs:metadata", "fs"),
            ("net:connect", "net"),
            ("http:request", "http"),
            ("shell:exec", "shell"),
            ("shell:spawn", "shell"),
            ("mcp:call", "mcp"),
            ("lookup", "server"),
            ("unknown", "unknown"),
        ];
        let mut interval =
            DecisionInterval::new(invocation.started(), ActionCatalog::new(["server".into()]));
        for (action, category) in actions {
            for cause in [
                "permitted",
                "forbidden",
                "no_match",
                "policy_pending",
                "internal_fault",
                "enforcement",
                "unknown",
            ] {
                interval.observe(Decision {
                    action: action.into(),
                    category: category.into(),
                    verdict: if cause == "permitted" {
                        Verdict::Permit
                    } else {
                        Verdict::Deny
                    },
                    cause: Some(cause.into()),
                });
            }
        }
        let run = validate(&invocation.run_event(LaunchOutcome::Unknown));
        let polling = validate(
            &invocation.polling_event(
                interval
                    .finish(invocation.started() + Duration::from_secs(60), true)
                    .unwrap(),
            ),
        );
        assert_eq!(polling["event"], "polling/1");
        assert_eq!(polling["data"]["interval_duration_ms"], 60_000);
        let decisions = polling["data"]["decisions"].as_array().unwrap();
        assert_eq!(decisions.len(), 84);
        assert!(decisions.iter().all(|row| row["count"] == 1));
        for key in ["v", "installation_id", "run_id", "context"] {
            assert_eq!(polling[key], run[key], "{key}");
        }
        let empty = validate(
            &invocation.polling_event(interval.finish(invocation.started(), true).unwrap()),
        );
        assert_eq!(empty["data"]["decisions"], json!([]));
    }
}
