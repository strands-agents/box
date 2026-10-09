//! An inactive adapter that submits native filesystem requests to the hosted authority without installing kernel hooks.

use std::path::Path;
use std::sync::Arc;

use policy::{
    ApprovedPath, Decision, FsOperation, FsResult, GovernedBox, Outcome, PolicyEngine, PolicyError,
    Principal, Request,
};

/// Submits individual filesystem checks to the authority the hosted box already owns.
pub(super) struct NativePolicy {
    policy: Arc<PolicyEngine>,
    governed: GovernedBox,
    record_outcome: RecordOutcome,
}

type RecordOutcome =
    fn(&PolicyEngine, &GovernedBox, &Principal, &Outcome<'_>) -> Result<(), PolicyError>;

impl NativePolicy {
    pub(super) fn new(policy: Arc<PolicyEngine>, governed: GovernedBox) -> Self {
        Self {
            policy,
            governed,
            record_outcome: PolicyEngine::record,
        }
    }

    /// Records a permission request without performing an operation or recording its outcome.
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "Native callbacks are not connected yet")
    )]
    pub(super) fn decide(&self, path: &ApprovedPath, operation: FsOperation) -> Decision {
        self.policy.decide(
            &self.governed,
            &Principal::agent(),
            &Request::Fs { path, operation },
        )
    }

    /// Records the caller's observed outcome with the same path spelling as the request.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "Native callbacks are not connected yet")
    )]
    pub(super) fn record(
        &self,
        path: &ApprovedPath,
        operation: FsOperation,
        result: FsResult,
    ) -> Result<(), PolicyError> {
        (self.record_outcome)(
            &self.policy,
            &self.governed,
            &Principal::agent(),
            &Outcome::Fs {
                path: Path::new(path.reported().as_ref()),
                operation,
                result,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy::{DenyReason, PathResolver, Policy, ShellPolicyInterceptor};
    use strands_shell::Shell;

    fn engine(directory: &Path, source: &str) -> Arc<PolicyEngine> {
        Arc::new(
            PolicyEngine::open(
                vec![Policy {
                    origin: directory.join("policy.dw"),
                    text: source.to_string(),
                }],
                &directory.join("history.redb"),
            )
            .expect("policy opens"),
        )
    }

    fn path(home: &Path, name: &str) -> ApprovedPath {
        PathResolver::over([home.to_path_buf()])
            .expect("reachable home")
            .reporting_under(home)
            .approve_host(&home.join(name))
            .expect("approved path")
    }

    #[test]
    fn native_checks_keep_the_existing_actions_identity_and_path_spelling() {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().canonicalize().unwrap();
        let adapter = NativePolicy::new(
            engine(
                &home,
                r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.path == "~/read" && context.input.operation == Box::FsReadOperation::"read_content" };
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when { context.input.path == "~/write" && context.input.operation == Box::FsWriteOperation::"write_content" };
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource)
when { context.input.path == "~/move" && context.input.operation == Box::FsMoveOperation::"rename" };
permit(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource)
when { context.input.path == "~/delete" && context.input.operation == Box::FsDeleteOperation::"remove_file" };
"#,
            ),
            GovernedBox::assigned("native-test"),
        );
        for (name, operation) in [
            ("read", FsOperation::ReadContent),
            ("write", FsOperation::WriteContent),
            ("move", FsOperation::Rename),
            ("delete", FsOperation::RemoveFile),
        ] {
            let approved = path(&home, name);
            assert!(adapter.decide(&approved, operation).is_allow(), "{name}");
            assert!(
                matches!(
                    adapter.decide(&path(&home, "unlisted"), operation),
                    Decision::Deny {
                        reason: DenyReason::NoMatch,
                        ..
                    }
                ),
                "{name} must not grant other paths"
            );
            assert!(!approved.as_path().exists(), "a decision performs no I/O");
        }
    }

    #[test]
    fn admission_does_not_record_completion_and_outcomes_keep_request_spelling() {
        for (result, event) in [
            (
                FsResult::Completed,
                r#"response{ input.path: "~/source", output.result: Box::FsResponseResult::"completed" }"#,
            ),
            (
                FsResult::DescriptorIssued,
                r#"response{ input.path: "~/source", output.result: Box::FsResponseResult::"descriptor_issued" }"#,
            ),
            (
                FsResult::Indeterminate,
                r#"response{ input.path: "~/source", output.result: Box::FsResponseResult::"indeterminate" }"#,
            ),
            (FsResult::Failed, r#"error{ input.path: "~/source" }"#),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let home = directory.path().canonicalize().unwrap();
            let source = format!(
                r#"
permit(principal, action == Box::Action::"fs:write", resource);
forbid(principal, action == Box::Action::"fs:write", resource)
when {{ context.input.path == "~/probe" }}
when temporal {{
    formerly within 3600s (Box::Action::"fs:write"::{event})
}};
"#
            );
            let adapter =
                NativePolicy::new(engine(&home, &source), GovernedBox::assigned("native-test"));
            let source = path(&home, "source");
            let probe = path(&home, "probe");
            assert!(
                adapter
                    .decide(&source, FsOperation::WriteContent)
                    .is_allow()
            );
            assert!(adapter.decide(&probe, FsOperation::WriteContent).is_allow());
            adapter
                .record(&source, FsOperation::WriteContent, result)
                .unwrap();
            assert!(
                matches!(
                    adapter.decide(&probe, FsOperation::WriteContent),
                    Decision::Deny {
                        reason: DenyReason::Forbidden,
                        ..
                    }
                ),
                "{result:?} must reach history with the request's path"
            );
            assert!(
                !source.as_path().exists(),
                "outcome recording performs no effect"
            );
        }
    }

    #[test]
    fn a_recording_error_reaches_the_caller() {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().canonicalize().unwrap();
        let mut adapter = NativePolicy::new(
            engine(
                &home,
                r#"permit(principal, action == Box::Action::"fs:write", resource);"#,
            ),
            GovernedBox::assigned("native-test"),
        );
        let target = path(&home, "source");
        assert!(
            adapter
                .decide(&target, FsOperation::WriteContent)
                .is_allow()
        );
        adapter.record_outcome = |_, _, _, _| {
            Err(PolicyError::Evaluation(
                "controlled recording failure".to_string(),
            ))
        };
        let error = adapter
            .record(&target, FsOperation::WriteContent, FsResult::Completed)
            .expect_err("a failed record must not appear successful");
        assert!(
            matches!(error, PolicyError::Evaluation(ref reason) if reason == "controlled recording failure"),
            "{error}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shell_and_native_checks_share_one_history() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let directory = tempfile::tempdir().unwrap();
                let home = directory.path().canonicalize().unwrap();
                std::fs::write(home.join("source"), "payload").unwrap();
                let policy = engine(
                    &home,
                    r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
forbid(principal, action == Box::Action::"fs:write", resource)
when { context.input.path == "~/probe" }
when temporal {
    formerly within 3600s (Box::Action::"fs:read"::response{ input.path: "~/source" })
};
forbid(principal, action == Box::Action::"fs:read", resource)
when { context.input.path == "~/source" }
when temporal {
    formerly within 3600s (Box::Action::"fs:write"::request{ input.path: "~/native-marker" })
};
"#,
                );
                let governed = GovernedBox::assigned("native-test");
                let adapter = NativePolicy::new(Arc::clone(&policy), governed.clone());
                let interceptor = ShellPolicyInterceptor::into_handle_reporting_under(
                    policy,
                    Principal::agent(),
                    governed,
                    &home,
                );
                let mut shell = Shell::builder()
                    .bind_direct(home.display().to_string(), home.display().to_string())
                    .effect_interceptor(interceptor)
                    .build()
                    .unwrap();
                let probe = path(&home, "probe");
                assert!(adapter.decide(&probe, FsOperation::WriteContent).is_allow());
                let read = format!("cat {}/source", home.display());
                let output = shell.run(&read).await;
                assert_eq!(output.status, 0, "{}", output.stderr);
                assert!(!adapter.decide(&probe, FsOperation::WriteContent).is_allow());
                assert!(
                    adapter
                        .decide(&path(&home, "native-marker"), FsOperation::WriteContent)
                        .is_allow()
                );
                let output = shell.run(&read).await;
                assert_ne!(output.status, 0, "Shell must see the native request");
            })
            .await;
    }
}
