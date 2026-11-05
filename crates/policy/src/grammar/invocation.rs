//! One command line that a grammar read, as the `context.input` record its grammar action decides.

use std::path::Path;

use super::model::UNMODELED_ACTION;
use super::shell_grammar::{BASE_FIELDS, FieldValue, Parsed};
use super::{Grammar, ProgramFile};
use crate::Decision;
use crate::path::ApprovedPath;
use crate::schema::ActionIdentity;

/// One spawn of a grammar-bound program, and what its grammar reads the command line as.
pub(crate) struct GrammarInvocation<'a> {
    grammar: &'a Grammar,
    parsed: Parsed,
    program: &'a str,
    program_path: String,
    cwd: &'a str,
    args: &'a [String],
    credential_reads: &'a [String],
}

/// The `::response` that an allowed grammar action owes, holding the exact action and input.
#[must_use = "a dropped pending response is a `::response` that history never sees"]
pub(crate) struct PendingGrammarResponse {
    identity: ActionIdentity,
    input: serde_json::Value,
}

impl PendingGrammarResponse {
    /// Hand the decided action and input to `record`, once.
    pub(crate) fn complete<T>(
        self,
        record: impl FnOnce(&ActionIdentity, &serde_json::Value) -> T,
    ) -> T {
        record(&self.identity, &self.input)
    }
}

/// One grammar action as the engine decides it: its identity, its input, and the program it names.
pub(crate) struct GrammarRequest {
    identity: ActionIdentity,
    input: serde_json::Value,
    program_path: String,
}

impl GrammarRequest {
    pub(crate) fn identity(&self) -> &ActionIdentity {
        &self.identity
    }

    /// The `context.input` record in Cedar's JSON form, with each effect as an `__entity` escape.
    pub(crate) fn input(&self) -> &serde_json::Value {
        &self.input
    }

    /// The resource that the verdict names: the resolved program, as on a `shell:spawn`.
    pub(crate) fn resource(&self) -> &str {
        &self.program_path
    }

    /// This request with `input` in place of the record its command line gives.
    #[cfg(test)]
    pub(crate) fn with_input(self, input: serde_json::Value) -> Self {
        Self { input, ..self }
    }

    /// The `::response` that this action owes when `decision` allows it.
    pub(crate) fn allowed_by(self, decision: &Decision) -> Option<PendingGrammarResponse> {
        decision.is_allow().then_some(PendingGrammarResponse {
            identity: self.identity,
            input: self.input,
        })
    }
}

impl<'a> GrammarInvocation<'a> {
    /// Read `args`, the words after `program`, with the shell grammar of `grammar`, for a spawn of
    /// `program_file` that a rule reads home-relative under `home`.
    pub(crate) fn new(
        grammar: &'a Grammar,
        program: &'a str,
        program_file: &ProgramFile,
        home: Option<&Path>,
        cwd: &'a str,
        args: &'a [String],
        credential_reads: &'a [String],
    ) -> Self {
        Self {
            grammar,
            parsed: grammar.shell().parse(args),
            program,
            program_path: ApprovedPath::under_home(program_file.path(), home)
                .reported()
                .into_owned(),
            cwd,
            args,
            credential_reads,
        }
    }

    /// The action the parse names: its own action, or `unmodeled`.
    fn action(&self) -> &str {
        match &self.parsed {
            Parsed::Action { action, .. } => action.as_str(),
            Parsed::Unmodeled => UNMODELED_ACTION,
        }
    }

    fn identity(&self) -> ActionIdentity {
        ActionIdentity::GrammarAction {
            namespace: self.grammar.namespace(),
            action: self.action().to_string(),
        }
    }

    fn input(&self) -> serde_json::Value {
        let [
            program,
            program_path,
            cwd,
            args,
            effects_field,
            credential_reads,
        ] = BASE_FIELDS;
        let mut sorted = self.args.to_vec();
        sorted.sort();
        sorted.dedup();
        let mut record = serde_json::Map::new();
        record.insert(program.to_string(), self.program.into());
        record.insert(program_path.to_string(), self.program_path.as_str().into());
        record.insert(cwd.to_string(), self.cwd.into());
        record.insert(args.to_string(), sorted.into());
        if !self.credential_reads.is_empty() {
            record.insert(credential_reads.to_string(), self.credential_reads.into());
        }
        let (fields, effects) = match &self.parsed {
            Parsed::Action {
                fields, effects, ..
            } => (Some(fields), effects.iter().collect()),
            Parsed::Unmodeled => (None, Vec::new()),
        };
        if !self.grammar.effects.is_empty() {
            let effect_type = format!("{}::Effect", self.grammar.namespace());
            let effects: Vec<serde_json::Value> = effects
                .into_iter()
                .map(|effect| {
                    serde_json::json!({ "__entity": { "type": effect_type, "id": effect.as_str() } })
                })
                .collect();
            record.insert(effects_field.to_string(), effects.into());
        }
        for (name, value) in fields.into_iter().flatten() {
            let value = match value {
                FieldValue::Bool(value) => serde_json::Value::from(*value),
                FieldValue::String(value) => serde_json::Value::from(value.as_str()),
                FieldValue::Set(values) => serde_json::Value::from(values.as_slice()),
            };
            record.insert(name.clone(), value);
        }
        serde_json::Value::Object(record)
    }

    /// The grammar action this command line raises, as a rule spells it.
    pub(crate) fn action_name(&self) -> String {
        self.identity().observer_action().into_owned()
    }

    /// The grammar action this command line raises, with its exact `context.input` record.
    pub(crate) fn request(&self) -> GrammarRequest {
        GrammarRequest {
            identity: self.identity(),
            input: self.input(),
            program_path: self.program_path.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use super::super::corpus::{Engine, GRAMMARS};
    use super::*;
    use crate::{Decision, DecisionObserver, DenyReason, GovernedBox, Principal, Request};

    fn valid(name: &str) -> Grammar {
        Grammar::load(
            &Path::new(GRAMMARS)
                .join("valid")
                .join(format!("{name}.grammar.toml")),
        )
        .expect("the fixture grammar loads")
    }

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(ToString::to_string).collect()
    }

    fn forbidden_by(decision: &Decision, id: &str) -> bool {
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::Forbidden,
                ..
            }
        ) && decision
            .attribution()
            .iter()
            .any(|attribution| attribution.annotation_id.as_deref() == Some(id))
    }

    const PUSH_AFTER_A_PASSING_TEST: &str = r#"
        permit (principal, action in Tool::git::Action::"*", resource);
        permit (principal, action in Tool::cargo::Action::"*", resource);
        @id("push_after_a_passing_test")
        forbid (principal, action == Tool::git::Action::"push", resource)
        unless temporal {
            formerly within 1h Tool::cargo::Action::"test"::response{ output.status: 0 }
        };
    "#;

    #[test]
    fn a_temporal_rule_reads_the_exit_status_that_a_grammar_response_records() {
        let grammars = [valid("git"), valid("cargo")];
        let engine = Engine::open(PUSH_AFTER_A_PASSING_TEST, &grammars).expect("the engine opens");
        let [git, cargo] = &grammars;
        let push = argv(&["git", "push", "origin", "main"]);
        let test = argv(&["cargo", "test"]);
        let tested = |cargo: &Grammar, test: &[String], status: i32| {
            let (decision, pending) = engine.invoke(cargo, test);
            assert!(decision.is_allow(), "the test run is allowed: {decision:?}");
            engine
                .engine()
                .record_grammar_response(
                    pending.expect("an allowed action owes a response"),
                    status,
                )
                .expect("history records the response");
        };

        assert!(
            forbidden_by(&engine.decide(git, &push), "push_after_a_passing_test"),
            "no test has run, so the push is refused"
        );
        tested(cargo, &test, 1);
        assert!(
            forbidden_by(&engine.decide(git, &push), "push_after_a_passing_test"),
            "a test that exited 1 must not satisfy `output.status: 0`"
        );
        tested(cargo, &test, 0);
        assert!(
            engine.decide(git, &push).is_allow(),
            "a test that exited 0 satisfies `output.status: 0`"
        );
    }

    #[test]
    fn a_denied_grammar_action_owes_no_response() {
        let git = valid("git");
        let engine = Engine::open(
            r#"permit (principal, action == Tool::git::Action::"status", resource);"#,
            std::slice::from_ref(&git),
        )
        .expect("the engine opens");

        let (allowed, owed) = engine.invoke(&git, &argv(&["git", "status"]));
        let (denied, none) = engine.invoke(&git, &argv(&["git", "push", "origin", "main"]));

        assert!(allowed.is_allow() && owed.is_some(), "{allowed:?}");
        assert!(!denied.is_allow() && none.is_none(), "{denied:?}");
    }

    #[test]
    fn the_response_holds_the_action_and_the_input_that_were_decided() {
        let git = valid("git");
        let engine = Engine::open(
            "permit (principal, action, resource);",
            std::slice::from_ref(&git),
        )
        .expect("the engine opens");
        let args = argv(&["push", "--force", "origin", "main"]);
        let git_file = ProgramFile::fixed("/usr/bin/git", 1);
        let invocation = GrammarInvocation::new(&git, "git", &git_file, None, "/work", &args, &[]);

        let (decision, pending) = engine.engine().decide_grammar_action(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &invocation,
        );
        let recorded = pending
            .expect("an allowed action owes a response")
            .complete(|identity, input| (identity.clone(), input.clone()));

        assert!(decision.is_allow(), "{decision:?}");
        let request = invocation.request();
        assert_eq!(
            recorded,
            (request.identity().clone(), request.input().clone())
        );
    }

    const NO_SPAWN_AFTER_A_PUSH: &str = r#"
        permit (principal, action in Tool::git::Action::"*", resource);
        permit (principal, action == Box::Action::"shell:spawn", resource);
        @id("no_spawn_after_a_push")
        forbid (principal, action == Box::Action::"shell:spawn", resource)
        when temporal {
            formerly within 1h Tool::git::Action::"push"::request{ input.program: "git" }
        };
    "#;

    #[derive(Default)]
    struct Recording(Mutex<Vec<(String, String, bool)>>);

    impl DecisionObserver for Recording {
        fn observed(&self, action: &str, resource: &str, decision: &Decision) {
            self.0.lock().expect("the recording lock").push((
                action.to_string(),
                resource.to_string(),
                decision.is_allow(),
            ));
        }
    }

    #[test]
    fn a_grammar_decision_enters_the_one_history_and_reaches_the_observer() {
        let git = valid("git");
        let recording = Arc::new(Recording::default());
        let engine = Engine::open(NO_SPAWN_AFTER_A_PUSH, std::slice::from_ref(&git))
            .expect("the engine opens")
            .observed_by(recording.clone());
        let words = argv(&["make"]);
        let spawn = Request::ShellSpawn {
            command: "make",
            program: "make",
            program_path: "/usr/bin/make",
            credential_reads: &[],
            args: &words[1..],
            cwd: "/work",
        };
        let spawned = || {
            engine.engine().decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &spawn,
            )
        };

        assert!(
            spawned().is_allow(),
            "no push has run, so the spawn is allowed"
        );
        assert!(
            engine
                .decide(&git, &argv(&["git", "push", "origin", "main"]))
                .is_allow()
        );
        assert!(
            forbidden_by(&spawned(), "no_spawn_after_a_push"),
            "the push is in the history that the spawn rule reads"
        );
        assert_eq!(
            recording.0.lock().expect("the recording lock").as_slice(),
            [
                (
                    r#"Box::Action::"shell:spawn""#.to_string(),
                    "/usr/bin/make".to_string(),
                    true
                ),
                (
                    r#"Tool::git::Action::"push""#.to_string(),
                    "/usr/bin/git".to_string(),
                    true
                ),
                (
                    r#"Box::Action::"shell:spawn""#.to_string(),
                    "/usr/bin/make".to_string(),
                    false
                ),
            ]
        );
    }
}
