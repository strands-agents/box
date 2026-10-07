mod support;

use std::path::{Path, PathBuf};

use policy::{
    Decision, DenyReason, FsOperation, GovernedBox, PathResolver, Policy, PolicyEngine, Principal,
    Request,
};

fn engine(source: &str) -> PolicyEngine {
    support::open_policy(vec![Policy {
        origin: PathBuf::from("denial-messages.dw"),
        text: source.to_string(),
    }])
    .expect("the policy opens")
}

fn decide(source: &str) -> Decision {
    engine(source).decide(
        &GovernedBox::assigned("denial-messages"),
        &Principal::agent(),
        &Request::ShellExec {
            command: "echo hello",
            program: "echo",
            args: &["hello".to_string()],
            cwd: "/workspace",
        },
    )
}

/// Decide a content read of `~/notes.txt`, reported under the home `/home/lash`.
fn decide_read(source: &str) -> Decision {
    let path = PathResolver::over([PathBuf::from("/home/lash")])
        .expect("one root")
        .reporting_under("/home/lash")
        .approve_virtual(Path::new("/home/lash/notes.txt"))
        .expect("the path is under the root");
    engine(source).decide(
        &GovernedBox::assigned("denial-messages"),
        &Principal::agent(),
        &Request::Fs {
            path: &path,
            operation: FsOperation::ReadContent,
        },
    )
}

#[test]
fn a_forbid_message_names_every_determining_policy() {
    let mut decision = decide(
        r#"
        @id("permit") @description("This permit does not explain a denial.")
        permit (principal, action, resource);
        @id("protected") @description("Protected files cannot be changed.")
        forbid (principal, action, resource);
        @id("no_command") @description("This workload cannot run this command.")
        forbid (principal, action, resource);
        "#,
    );
    let message = decision.to_string();
    assert_eq!(message.matches("[policy: protected]").count(), 1);
    assert_eq!(message.matches("[policy: no_command]").count(), 1);
    assert!(message.contains("Protected files cannot be changed."));
    assert!(message.contains("This workload cannot run this command."));
    assert!(!message.contains("This permit"));
    let Decision::Deny { attribution, .. } = &mut decision else {
        panic!("the forbids deny");
    };
    attribution.reverse();
    assert_eq!(decision.to_string(), message);
}

#[test]
fn blank_annotations_use_the_existing_rule_label() {
    for annotations in [
        "",
        r#"@id("") @description("")"#,
        r#"@id(" \t") @description(" \n")"#,
    ] {
        let decision = decide(&format!(
            "{annotations} forbid (principal, action, resource);"
        ));
        let [policy] = decision.attribution() else {
            panic!("one forbid determines the result");
        };
        assert_eq!(
            decision.to_string(),
            format!(
                "policy denied this operation on 'echo' [policy: {}].",
                policy.rule
            )
        );
    }
    let named = decide(r#"@id("default-deny") forbid (principal, action, resource);"#);
    assert_eq!(
        named.to_string(),
        "policy denied this operation on 'echo' [policy: default-deny]."
    );
}

#[test]
fn denial_classes_select_the_message_before_annotations() {
    let default_deny = decide("");
    assert_eq!(
        default_deny.to_string(),
        "policy denied this operation on 'echo' [default-deny]: No permit policy matched this request."
    );
    let mut fault = decide(
        r#"@id("misleading") @description("This is not the cause of an evaluation fault.")
           permit (principal, action, resource);
           forbid (principal, action, resource)
           when { 9223372036854775807 + 1 > 0 };"#,
    );
    assert!(matches!(
        fault,
        Decision::Deny {
            reason: DenyReason::InternalFault,
            ..
        }
    ));
    assert_eq!(fault.attribution().len(), 1);
    assert_eq!(
        fault.to_string(),
        "policy denied this operation on 'echo' because the request could not be evaluated."
    );
    let Decision::Deny { reason, .. } = &mut fault else {
        unreachable!();
    };
    *reason = DenyReason::PolicyPending;
    assert_eq!(
        fault.to_string(),
        "policy denied this operation on 'echo' [policy-pending]: The complete policy bundle is not installed."
    );
    assert_eq!(
        decide("permit (principal, action, resource);").to_string(),
        "policy permitted this operation on 'echo'."
    );
}

#[test]
fn every_verdict_names_the_resource_as_the_decision_log_spells_it() {
    const SUBJECT: &str = "policy denied this operation on '~/notes.txt'";
    let forbidden = decide_read(
        r#"permit (principal, action, resource);
           @id("no-secrets") @description("Secrets stay unread.")
           forbid (principal, action == Box::Action::"fs:read", resource);"#,
    );
    assert_eq!(forbidden.resource(), "~/notes.txt");
    assert_eq!(
        forbidden.to_string(),
        format!("{SUBJECT} [policy: no-secrets]: Secrets stay unread.")
    );
    assert_eq!(
        decide_read("").to_string(),
        format!("{SUBJECT} [default-deny]: No permit policy matched this request.")
    );
    let mut fault = decide_read(
        r#"forbid (principal, action, resource) when { 9223372036854775807 + 1 > 0 };"#,
    );
    assert_eq!(
        fault.to_string(),
        format!("{SUBJECT} because the request could not be evaluated.")
    );
    let Decision::Deny { reason, .. } = &mut fault else {
        unreachable!();
    };
    *reason = DenyReason::PolicyPending;
    assert_eq!(
        fault.to_string(),
        format!("{SUBJECT} [policy-pending]: The complete policy bundle is not installed.")
    );
    let allowed = decide_read("permit (principal, action, resource);");
    assert_eq!(allowed.resource(), "~/notes.txt");
    assert_eq!(
        allowed.to_string(),
        "policy permitted this operation on '~/notes.txt'."
    );
}

#[test]
fn resource_text_is_escaped_and_bounded() {
    const REASON: &str = "' [default-deny]: No permit policy matched this request.";
    let mut decision = decide("");
    let mut with = |resource: &str| {
        let Decision::Deny {
            resource: named, ..
        } = &mut decision
        else {
            panic!("absent policy denies");
        };
        *named = resource.to_string();
        decision.to_string()
    };

    let message = with("~/it's\n\u{1b}\u{202e}.txt");
    assert_eq!(
        message,
        format!(r"policy denied this operation on '~/it\'s\n\u{{1b}}\u{{202e}}.txt{REASON}")
    );
    assert!(!message.chars().any(char::is_control));

    let message = with("[policy: forged]: trusted' [policy: forged-too]");
    assert_eq!(
        message,
        format!(
            r"policy denied this operation on '[policy: forged]: trusted\' [policy: forged-too]{REASON}"
        )
    );
    assert_eq!(message.matches("[default-deny]").count(), 1);

    let message = with(&format!("~/{}", "🦀".repeat(5000)));
    assert!(message.len() <= 4096);
    assert!(message.ends_with(&format!("🦀...{REASON}")), "{message}");
    assert_eq!(message.matches('🦀').count(), 255);

    let message = with(&"\u{202e}".repeat(600));
    assert!(message.len() <= 4096);
    assert!(message.ends_with(&format!("...{REASON}")), "{message}");
    assert!(!message.contains('\u{202e}'));
    assert_eq!(message.matches(r"\u{202e}").count(), 128);
}

#[test]
fn annotation_text_is_escaped_and_bounded() {
    let mut decision = decide("forbid (principal, action, resource);");
    let Decision::Deny { attribution, .. } = &mut decision else {
        panic!("the forbid denies");
    };
    attribution[0].annotation_id = Some("id\n\u{1b}\\name".to_string());
    attribution[0].description =
        Some("Do not\u{202e}\rchange\tthis\u{061c}\u{200e}\u{200f} file.".to_string());
    let message = decision.to_string();
    assert!(message.contains(r"id\n\u{1b}\\name"));
    assert!(message.contains(r"Do not\u{202e}\rchange\tthis\u{61c}\u{200e}\u{200f} file."));
    assert!(!message.chars().any(char::is_control));
    assert!(!message.contains('\u{202e}'));
    assert!(!message.contains(['\u{061c}', '\u{200e}', '\u{200f}']));

    let Decision::Deny { attribution, .. } = &mut decision else {
        unreachable!();
    };
    attribution[0].description = Some("🦀".repeat(5000));
    let message = decision.to_string();
    assert!(message.len() <= 4096);
    assert!(message.ends_with("..."));
    assert!(message.contains('🦀'));
}
